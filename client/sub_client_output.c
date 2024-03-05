/*
Copyright (c) 2009-2020 Roger Light <roger@atchoo.org>

All rights reserved. This program and the accompanying materials
are made available under the terms of the Eclipse Public License 2.0
and Eclipse Distribution License v1.0 which accompany this distribution.

The Eclipse Public License is available at
   https://www.eclipse.org/legal/epl-2.0/
and the Eclipse Distribution License is available at
  http://www.eclipse.org/org/documents/edl-v10.php.

SPDX-License-Identifier: EPL-2.0 OR BSD-3-Clause

Contributors:
   Roger Light - initial implementation and documentation.
*/

#include "config.h"

#ifdef WIN32
   /* For rand_s on Windows */
#  define _CRT_RAND_S
#  include <fcntl.h>
#  include <io.h>
#endif

#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#ifndef WIN32
#include <unistd.h>
#else
#include <process.h>
#include <winsock2.h>
#define snprintf sprintf_s
#endif

#ifdef WITH_CJSON
#  include <cjson/cJSON.h>
#endif

#ifdef __APPLE__
#  include <sys/time.h>
#endif

#include <mosquitto.h>
#include <mqtt_protocol.h>
#include "client_shared.h"
#include "sub_client_output.h"

#include <curl/curl.h>

#include "mbedtls/sha256.h"
#include "mbedtls/chacha20.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "secp256k1.h"
#include "secp256k1_ecdh.h"
#include "sqlite3.h"

#include "wtlib.h"

extern struct mosq_config cfg;

static int get_time(struct tm **ti, long *ns)
{
#ifdef WIN32
	SYSTEMTIME st;
#elif defined(__APPLE__)
	struct timeval tv;
#else
	struct timespec ts;
#endif
	time_t s;

#ifdef WIN32
	s = time(NULL);

	GetLocalTime(&st);
	*ns = st.wMilliseconds*1000000L;
#elif defined(__APPLE__)
	gettimeofday(&tv, NULL);
	s = tv.tv_sec;
	*ns = tv.tv_usec*1000;
#else
	if(clock_gettime(CLOCK_REALTIME, &ts) != 0){
		err_printf(&cfg, "Error obtaining system time.\n");
		return 1;
	}
	s = ts.tv_sec;
	*ns = ts.tv_nsec;
#endif

	*ti = localtime(&s);
	if(!(*ti)){
		err_printf(&cfg, "Error obtaining system time.\n");
		return 1;
	}

	return 0;
}


static void write_payload(const unsigned char *payload, int payloadlen, int hex, char align, char pad, int field_width, int precision)
{
	int i;
	int padlen;

	UNUSED(precision); /* FIXME - use or remove */

	if(field_width > 0){
		if(payloadlen > field_width){
			payloadlen = field_width;
		}
		if(hex > 0){
			payloadlen /= 2;
			padlen = field_width - payloadlen*2;
		}else{
			padlen = field_width - payloadlen;
		}
	}else{
		padlen = field_width - payloadlen;
	}

	if(align != '-'){
		for(i=0; i<padlen; i++){
			putchar(pad);
		}
	}

	if(hex == 0){
		(void)fwrite(payload, 1, (size_t )payloadlen, stdout);
	}else if(hex == 1){
		for(i=0; i<payloadlen; i++){
			fprintf(stdout, "%02x", payload[i]);
		}
	}else if(hex == 2){
		for(i=0; i<payloadlen; i++){
			fprintf(stdout, "%02X", payload[i]);
		}
	}

	if(align == '-'){
		printf("%*s", padlen, "");
	}
}


#ifndef WITH_CJSON
static void write_json_payload(const char *payload, int payloadlen)
{
	int i;

	for(i=0; i<payloadlen; i++){
		if(payload[i] == '"' || payload[i] == '\\' || (payload[i] >=0 && payload[i] < 32)){
			printf("\\u%04x", payload[i]);
		}else{
			fputc(payload[i], stdout);
		}
	}
}
#endif


#ifdef WITH_CJSON
static int json_print_properties(cJSON *root, const mosquitto_property *properties)
{
	int identifier;
	uint8_t i8value = 0;
	uint16_t i16value = 0;
	uint32_t i32value = 0;
	char *strname = NULL, *strvalue = NULL;
	char *binvalue = NULL;
	cJSON *tmp, *prop_json, *user_json = NULL;
	const mosquitto_property *prop = NULL;

	prop_json = cJSON_CreateObject();
	if(prop_json == NULL){
		cJSON_Delete(prop_json);
		return MOSQ_ERR_NOMEM;
	}
	cJSON_AddItemToObject(root, "properties", prop_json);

	for(prop=properties; prop != NULL; prop = mosquitto_property_next(prop)){
		tmp = NULL;
		identifier = mosquitto_property_identifier(prop);
		switch(identifier){
			case MQTT_PROP_PAYLOAD_FORMAT_INDICATOR:
				mosquitto_property_read_byte(prop, MQTT_PROP_PAYLOAD_FORMAT_INDICATOR, &i8value, false);
				tmp = cJSON_CreateNumber(i8value);
				break;

			case MQTT_PROP_MESSAGE_EXPIRY_INTERVAL:
				mosquitto_property_read_int32(prop, MQTT_PROP_MESSAGE_EXPIRY_INTERVAL, &i32value, false);
				tmp = cJSON_CreateNumber(i32value);
				break;

			case MQTT_PROP_CONTENT_TYPE:
			case MQTT_PROP_RESPONSE_TOPIC:
				mosquitto_property_read_string(prop, identifier, &strvalue, false);
				if(strvalue == NULL) return MOSQ_ERR_NOMEM;
				tmp = cJSON_CreateString(strvalue);
				free(strvalue);
				strvalue = NULL;
				break;

			case MQTT_PROP_CORRELATION_DATA:
				mosquitto_property_read_binary(prop, MQTT_PROP_CORRELATION_DATA, (void **)&binvalue, &i16value, false);
				if(binvalue == NULL) return MOSQ_ERR_NOMEM;
				tmp = cJSON_CreateString(binvalue);
				free(binvalue);
				binvalue = NULL;
				break;

			case MQTT_PROP_SUBSCRIPTION_IDENTIFIER:
				mosquitto_property_read_varint(prop, MQTT_PROP_SUBSCRIPTION_IDENTIFIER, &i32value, false);
				tmp = cJSON_CreateNumber(i32value);
				break;

			case MQTT_PROP_TOPIC_ALIAS:
				mosquitto_property_read_int16(prop, MQTT_PROP_TOPIC_ALIAS, &i16value, false);
				tmp = cJSON_CreateNumber(i16value);
				break;

			case MQTT_PROP_USER_PROPERTY:
				if(user_json == NULL){
					user_json = cJSON_CreateObject();
					if(user_json == NULL){
						return MOSQ_ERR_NOMEM;
					}
					cJSON_AddItemToObject(prop_json, "user-properties", user_json);
				}
				mosquitto_property_read_string_pair(prop, MQTT_PROP_USER_PROPERTY, &strname, &strvalue, false);
				if(strname == NULL || strvalue == NULL) return MOSQ_ERR_NOMEM;

				tmp = cJSON_CreateString(strvalue);
				free(strvalue);

				if(tmp == NULL){
					free(strname);
					return MOSQ_ERR_NOMEM;
				}
				cJSON_AddItemToObject(user_json, strname, tmp);
				free(strname);
				strname = NULL;
				strvalue = NULL;
				tmp = NULL; /* Don't add this to prop_json below */
				break;
		}
		if(tmp != NULL){
			cJSON_AddItemToObject(prop_json, mosquitto_property_identifier_to_string(identifier), tmp);
		}
	}
	return MOSQ_ERR_SUCCESS;
}
#endif


static void format_time_8601(const struct tm *ti, int ns, char *buf, size_t len)
{
	char c;

	strftime(buf, len, "%Y-%m-%dT%H:%M:%S.000000%z", ti);
	c = buf[strlen("2020-05-06T21:48:00.000000")];
	snprintf(&buf[strlen("2020-05-06T21:48:00.")], 9, "%06d", ns/1000);
	buf[strlen("2020-05-06T21:48:00.000000")] = c;
}

static int json_print(const struct mosquitto_message *message, const mosquitto_property *properties, const struct tm *ti, int ns, bool escaped, bool pretty)
{
	char buf[100];
#ifdef WITH_CJSON
	cJSON *root;
	cJSON *tmp;
	char *json_str;
	const char *return_parse_end;

	root = cJSON_CreateObject();
	if(root == NULL){
		return MOSQ_ERR_NOMEM;
	}

	format_time_8601(ti, ns, buf, sizeof(buf));

	tmp = cJSON_CreateStringReference(buf);
	if(tmp == NULL){
		cJSON_Delete(root);
		return MOSQ_ERR_NOMEM;
	}
	cJSON_AddItemToObject(root, "tst", tmp);

	tmp = cJSON_CreateString(message->topic);
	if(tmp == NULL){
		cJSON_Delete(root);
		return MOSQ_ERR_NOMEM;
	}

	cJSON_AddItemToObject(root, "topic", tmp);

	tmp = cJSON_CreateNumber(message->qos);
	if(tmp == NULL){
		cJSON_Delete(root);
		return MOSQ_ERR_NOMEM;
	}
	cJSON_AddItemToObject(root, "qos", tmp);

	tmp = cJSON_CreateNumber(message->retain);
	if(tmp == NULL){
		cJSON_Delete(root);
		return MOSQ_ERR_NOMEM;
	}
	cJSON_AddItemToObject(root, "retain", tmp);

	tmp = cJSON_CreateNumber(message->payloadlen);
	if(tmp == NULL){
		cJSON_Delete(root);
		return MOSQ_ERR_NOMEM;
	}
	cJSON_AddItemToObject(root, "payloadlen", tmp);

	if(message->qos > 0){
		tmp = cJSON_CreateNumber(message->mid);
		if(tmp == NULL){
			cJSON_Delete(root);
			return MOSQ_ERR_NOMEM;
		}
		cJSON_AddItemToObject(root, "mid", tmp);
	}

	/* Properties */
	if(properties){
		if(json_print_properties(root, properties)){
			cJSON_Delete(root);
			return MOSQ_ERR_NOMEM;
		}
	}

	/* Payload */
	if(escaped){
		if(message->payload){
			tmp = cJSON_CreateString(message->payload);
		}else{
			tmp = cJSON_CreateNull();
		}
		if(tmp == NULL){
			cJSON_Delete(root);
			return MOSQ_ERR_NOMEM;
		}
		cJSON_AddItemToObject(root, "payload", tmp);
	}else{
		return_parse_end = NULL;
		if(message->payload){
			tmp = cJSON_ParseWithOpts(message->payload, &return_parse_end, true);
			if(tmp == NULL || return_parse_end != (char *)message->payload + message->payloadlen){
				cJSON_Delete(root);
				return MOSQ_ERR_INVAL;
			}
		}else{
			tmp = cJSON_CreateNull();
			if(tmp == NULL){
				cJSON_Delete(root);
				return MOSQ_ERR_INVAL;
			}
		}
		cJSON_AddItemToObject(root, "payload", tmp);
	}

	if(pretty){
		json_str = cJSON_Print(root);
	}else{
		json_str = cJSON_PrintUnformatted(root);
	}
	cJSON_Delete(root);
	if(json_str == NULL){
		return MOSQ_ERR_NOMEM;
	}

	fputs(json_str, stdout);
	free(json_str);

	return MOSQ_ERR_SUCCESS;
#else
	UNUSED(properties);
	UNUSED(pretty);

	format_time_8601(ti, ns, buf, sizeof(buf));

	printf("{\"tst\":\"%s\",\"topic\":\"%s\",\"qos\":%d,\"retain\":%d,\"payloadlen\":%d,", buf, message->topic, message->qos, message->retain, message->payloadlen);
	if(message->qos > 0){
		printf("\"mid\":%d,", message->mid);
	}
	if(escaped){
		fputs("\"payload\":\"", stdout);
		write_json_payload(message->payload, message->payloadlen);
		fputs("\"}", stdout);
	}else{
		fputs("\"payload\":", stdout);
		write_payload(message->payload, message->payloadlen, 0, 0, 0, 0, 0);
		fputs("}", stdout);
	}

	return MOSQ_ERR_SUCCESS;
#endif
}


static void formatted_print_blank(char pad, int field_width)
{
	int i;
	for(i=0; i<field_width; i++){
		putchar(pad);
	}
}


static void formatted_print_int(int value, char align, char pad, int field_width)
{
	if(field_width == 0){
		printf("%d", value);
	}else{
		if(align == '-'){
			printf("%-*d", field_width, value);
		}else{
			if(pad == '0'){
				printf("%0*d", field_width, value);
			}else{
				printf("%*d", field_width, value);
			}
		}
	}
}


static void formatted_print_str(const char *value, char align, int field_width, int precision)
{
	if(field_width == 0 && precision == -1){
		fputs(value, stdout);
	}else{
		if(precision == -1){
			if(align == '-'){
				printf("%-*s", field_width, value);
			}else{
				printf("%*s", field_width, value);
			}
		}else if(field_width == 0){
			if(align == '-'){
				printf("%-.*s", precision, value);
			}else{
				printf("%.*s", precision, value);
			}
		}else{
			if(align == '-'){
				printf("%-*.*s", field_width, precision, value);
			}else{
				printf("%*.*s", field_width, precision, value);
			}
		}
	}
}

static void formatted_print_percent(const struct mosq_config *lcfg, const struct mosquitto_message *message, const mosquitto_property *properties, char format, char align, char pad, int field_width, int precision)
{
	struct tm *ti = NULL;
	long ns = 0;
	char buf[100];
	int rc;
	uint8_t i8value;
	uint16_t i16value;
	uint32_t i32value;
	char *binvalue = NULL, *strname, *strvalue;
	const mosquitto_property *prop;


	switch(format){
		case '%':
			fputc('%', stdout);
			break;

		case 'A':
			if(mosquitto_property_read_int16(properties, MQTT_PROP_TOPIC_ALIAS, &i16value, false)){
				formatted_print_int(i16value, align, pad, field_width);
			}else{
				formatted_print_blank(pad, field_width);
			}
			break;

		case 'C':
			if(mosquitto_property_read_string(properties, MQTT_PROP_CONTENT_TYPE, &strvalue, false)){
				formatted_print_str(strvalue, align, field_width, precision);
				free(strvalue);
			}else{
				formatted_print_blank(' ', field_width);
			}
			break;

		case 'D':
			if(mosquitto_property_read_binary(properties, MQTT_PROP_CORRELATION_DATA, (void **)&binvalue, &i16value, false)){
				fwrite(binvalue, 1, i16value, stdout);
				free(binvalue);
			}
			break;

		case 'E':
			if(mosquitto_property_read_int32(properties, MQTT_PROP_MESSAGE_EXPIRY_INTERVAL, &i32value, false)){
				formatted_print_int((int)i32value, align, pad, field_width);
			}else{
				formatted_print_blank(pad, field_width);
			}
			break;

		case 'F':
			if(mosquitto_property_read_byte(properties, MQTT_PROP_PAYLOAD_FORMAT_INDICATOR, &i8value, false)){
				formatted_print_int(i8value, align, pad, field_width);
			}else{
				formatted_print_blank(pad, field_width);
			}
			break;

		case 'I':
			if(!ti){
				if(get_time(&ti, &ns)){
					err_printf(lcfg, "Error obtaining system time.\n");
					return;
				}
			}
			if(strftime(buf, 100, "%FT%T%z", ti) != 0){
				formatted_print_str(buf, align, field_width, precision);
			}else{
				formatted_print_blank(' ', field_width);
			}
			break;

		case 'j':
			if(!ti){
				if(get_time(&ti, &ns)){
					err_printf(lcfg, "Error obtaining system time.\n");
					return;
				}
			}
			if(json_print(message, properties, ti, (int)ns, true, lcfg->pretty) != MOSQ_ERR_SUCCESS){
				err_printf(lcfg, "Error: Out of memory.\n");
				return;
			}
			break;

		case 'J':
			if(!ti){
				if(get_time(&ti, &ns)){
					err_printf(lcfg, "Error obtaining system time.\n");
					return;
				}
			}
			rc = json_print(message, properties, ti, (int)ns, false, lcfg->pretty);
			if(rc == MOSQ_ERR_NOMEM){
				err_printf(lcfg, "Error: Out of memory.\n");
				return;
			}else if(rc == MOSQ_ERR_INVAL){
				err_printf(lcfg, "Error: Message payload is not valid JSON on topic %s.\n", message->topic);
				return;
			}
			break;

		case 'l':
			formatted_print_int(message->payloadlen, align, pad, field_width);
			break;

		case 'm':
			formatted_print_int(message->mid, align, pad, field_width);
			break;

		case 'P':
			strname = NULL;
			strvalue = NULL;
			prop = mosquitto_property_read_string_pair(properties, MQTT_PROP_USER_PROPERTY, &strname, &strvalue, false);
			while(prop){
				printf("%s:%s", strname, strvalue);
				free(strname);
				free(strvalue);
				strname = NULL;
				strvalue = NULL;

				prop = mosquitto_property_read_string_pair(prop, MQTT_PROP_USER_PROPERTY, &strname, &strvalue, true);
				if(prop){
					fputc(' ', stdout);
				}
			}
			free(strname);
			free(strvalue);
			break;

		case 'p':
			write_payload(message->payload, message->payloadlen, 0, align, pad, field_width, precision);
			break;

		case 'q':
			fputc(message->qos + 48, stdout);
			break;

		case 'R':
			if(mosquitto_property_read_string(properties, MQTT_PROP_RESPONSE_TOPIC, &strvalue, false)){
				formatted_print_str(strvalue, align, field_width, precision);
				free(strvalue);
			}
			break;

		case 'r':
			if(message->retain){
				fputc('1', stdout);
			}else{
				fputc('0', stdout);
			}
			break;

		case 'S':
			if(mosquitto_property_read_varint(properties, MQTT_PROP_SUBSCRIPTION_IDENTIFIER, &i32value, false)){
				formatted_print_int((int)i32value, align, pad, field_width);
			}else{
				formatted_print_blank(pad, field_width);
			}
			break;

		case 't':
			formatted_print_str(message->topic, align, field_width, precision);
			break;

		case 'U':
			if(!ti){
				if(get_time(&ti, &ns)){
					err_printf(lcfg, "Error obtaining system time.\n");
					return;
				}
			}
			if(strftime(buf, 100, "%s", ti) != 0){
				printf("%s.%09ld", buf, ns);
			}
			break;

		case 'x':
			write_payload(message->payload, message->payloadlen, 1, align, pad, field_width, precision);
			break;

		case 'X':
			write_payload(message->payload, message->payloadlen, 2, align, pad, field_width, precision);
			break;
	}
}


static void formatted_print(const struct mosq_config *lcfg, const struct mosquitto_message *message, const mosquitto_property *properties)
{
	size_t len;
	size_t i;
	struct tm *ti = NULL;
	long ns = 0;
	char strf[3] = {0, 0 ,0};
	char buf[100];
	char align, pad;
	int field_width, precision;

	len = strlen(lcfg->format);

	for(i=0; i<len; i++){
		if(lcfg->format[i] == '%'){
			align = 0;
			pad = ' ';
			field_width = 0;
			precision = -1;
			if(i < len-1){
				i++;
				/* Optional alignment */
				if(lcfg->format[i] == '-'){
					align = lcfg->format[i];
					if(i < len-1){
						i++;
					}
				}
				/* "%-040p" is allowed by this combination of checks, but isn't
				 * a valid format specifier, the '0' will be ignored. */
				/* Optional zero padding */
				if(lcfg->format[i] == '0'){
					pad = '0';
					if(i < len-1){
						i++;
					}
				}
				/* Optional field width */
				while(i < len-1 && lcfg->format[i] >= '0' && lcfg->format[i] <= '9'){
					field_width *= 10;
					field_width += lcfg->format[i]-'0';
					i++;
				}
				/* Optional precision */
				if(lcfg->format[i] == '.'){
					if(i < len-1){
						i++;
						precision = 0;
						while(i < len-1 && lcfg->format[i] >= '0' && lcfg->format[i] <= '9'){
							precision *= 10;
							precision += lcfg->format[i]-'0';
							i++;
						}
					}
				}

				if(i < len){
					formatted_print_percent(lcfg, message, properties, lcfg->format[i], align, pad, field_width, precision);
				}
			}
		}else if(lcfg->format[i] == '@'){
			if(i < len-1){
				i++;
				if(lcfg->format[i] == '@'){
					fputc('@', stdout);
				}else{
					if(!ti){
						if(get_time(&ti, &ns)){
							err_printf(lcfg, "Error obtaining system time.\n");
							return;
						}
					}

					strf[0] = '%';
					strf[1] = lcfg->format[i];
					strf[2] = 0;

					if(lcfg->format[i] == 'N'){
						printf("%09ld", ns);
					}else{
						if(strftime(buf, 100, strf, ti) != 0){
							fputs(buf, stdout);
						}
					}
				}
			}
		}else if(lcfg->format[i] == '\\'){
			if(i < len-1){
				i++;
				switch(lcfg->format[i]){
					case '\\':
						fputc('\\', stdout);
						break;

					case '0':
						fputc('\0', stdout);
						break;

					case 'a':
						fputc('\a', stdout);
						break;

					case 'e':
						fputc('\033', stdout);
						break;

					case 'n':
						fputc('\n', stdout);
						break;

					case 'r':
						fputc('\r', stdout);
						break;

					case 't':
						fputc('\t', stdout);
						break;

					case 'v':
						fputc('\v', stdout);
						break;
				}
			}
		}else{
			fputc(lcfg->format[i], stdout);
		}
	}
	if(lcfg->eol){
		fputc('\n', stdout);
	}
	fflush(stdout);
}


void output_init(void)
{
#ifndef WIN32
	struct tm *ti = NULL;
	long ns;

	if(!get_time(&ti, &ns)){
		srandom((unsigned int)ns);
	}
#else
	/* Disable text translation so binary payloads aren't modified */
	_setmode(_fileno(stdout), _O_BINARY);
#endif
}

/* ========================================================================================================== */

bool wt_GenerateRandomeData(unsigned char* buf, unsigned int len)
{
	bool bRet = false;

	mbedtls_entropy_context entropy;
	mbedtls_ctr_drbg_context ctr_drbg;

	mbedtls_entropy_init(&entropy);
	mbedtls_ctr_drbg_init(&ctr_drbg);
	if (mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, NULL, 0) != 0) 
	{
		//fprintf(stdout, "Cannot mbedtls_ctr_drbg_seed\n");	
		return false;
	}

	if (mbedtls_ctr_drbg_random(&ctr_drbg, buf, len) == 0) 
	{
		//fprintf(stdout, "Looks good\n");	
		bRet = true;
	}

	return bRet;
}

// we have the 32-byte secret key, we want to generate the public key, return 0 if successful
static U32 wt_GenPublicKeyFromSecretKey(U8* sk, U8* pk)
{
	U32 ret = WT_FAIL;
	secp256k1_context* ctx;

	ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
	if (ctx)
	{
		int return_val;
		size_t len = 33;
		U8 compressed_pubkey[33];
		secp256k1_pubkey pubkey;

		return_val = secp256k1_ec_pubkey_create(ctx, &pubkey, sk);
		if (1 == return_val)
		{
			return_val = secp256k1_ec_pubkey_serialize(ctx, compressed_pubkey, &len, &pubkey, SECP256K1_EC_COMPRESSED);
			if (len == 33 && return_val == 1 && pk)
			{
				for (int i = 0; i < 33; i++) pk[i] = compressed_pubkey[i];
				ret = WT_OK;
			}
		}
		secp256k1_context_destroy(ctx);
	}
	return ret;
}

static int wt_Raw2HexString(unsigned char* input, unsigned char len, unsigned char* output, unsigned char* outlen)
{
	unsigned char idx, i;
	const unsigned char* hex_chars = (const unsigned char*)"0123456789ABCDEF";

	for (i = 0; i < len; i++)
	{
		idx = ((input[i] >> 4) & 0x0F);
		output[(i << 1)] = hex_chars[idx];

		idx = (input[i] & 0x0F);
		output[(i << 1) + 1] = hex_chars[idx];
	}

	output[(i << 1)] = 0;
	if (outlen)
		*outlen = (i << 1);

	return 0;
}

static U32 GetKeyFromSecretKeyAndPlubicKey(U8* sk, U8* pk, U8* key)
{
	U32 ret = WT_FAIL;

	secp256k1_context* ctx;

	ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
	if (ctx)
	{
		int rc;
		secp256k1_pubkey pubkey;
		U8 k[32] = { 0 };

		rc = secp256k1_ec_pubkey_parse(ctx, &pubkey, pk, 33);
		if (1 != rc)
		{
			secp256k1_context_destroy(ctx);
			return WT_SECP256K1_CTX_ERROR;
		}
		rc = secp256k1_ecdh(ctx, k, &pubkey, sk, NULL, NULL);
		if (1 == rc)
		{
			for (int i = 0; i < 32; i++)
			{
				key[i] = k[i];
				k[i] = 0;
			}
			ret = WT_OK;
		}
		secp256k1_context_destroy(ctx);
	}
	return ret;
}

static unsigned int crc32_tab[] =
{
	0x00000000, 0x77073096, 0xee0e612c, 0x990951ba, 0x076dc419,
	0x706af48f, 0xe963a535, 0x9e6495a3, 0x0edb8832, 0x79dcb8a4,
	0xe0d5e91e, 0x97d2d988, 0x09b64c2b, 0x7eb17cbd, 0xe7b82d07,
	0x90bf1d91, 0x1db71064, 0x6ab020f2, 0xf3b97148, 0x84be41de,
	0x1adad47d, 0x6ddde4eb, 0xf4d4b551, 0x83d385c7, 0x136c9856,
	0x646ba8c0, 0xfd62f97a, 0x8a65c9ec, 0x14015c4f, 0x63066cd9,
	0xfa0f3d63, 0x8d080df5, 0x3b6e20c8, 0x4c69105e, 0xd56041e4,
	0xa2677172, 0x3c03e4d1, 0x4b04d447, 0xd20d85fd, 0xa50ab56b,
	0x35b5a8fa, 0x42b2986c, 0xdbbbc9d6, 0xacbcf940, 0x32d86ce3,
	0x45df5c75, 0xdcd60dcf, 0xabd13d59, 0x26d930ac, 0x51de003a,
	0xc8d75180, 0xbfd06116, 0x21b4f4b5, 0x56b3c423, 0xcfba9599,
	0xb8bda50f, 0x2802b89e, 0x5f058808, 0xc60cd9b2, 0xb10be924,
	0x2f6f7c87, 0x58684c11, 0xc1611dab, 0xb6662d3d, 0x76dc4190,
	0x01db7106, 0x98d220bc, 0xefd5102a, 0x71b18589, 0x06b6b51f,
	0x9fbfe4a5, 0xe8b8d433, 0x7807c9a2, 0x0f00f934, 0x9609a88e,
	0xe10e9818, 0x7f6a0dbb, 0x086d3d2d, 0x91646c97, 0xe6635c01,
	0x6b6b51f4, 0x1c6c6162, 0x856530d8, 0xf262004e, 0x6c0695ed,
	0x1b01a57b, 0x8208f4c1, 0xf50fc457, 0x65b0d9c6, 0x12b7e950,
	0x8bbeb8ea, 0xfcb9887c, 0x62dd1ddf, 0x15da2d49, 0x8cd37cf3,
	0xfbd44c65, 0x4db26158, 0x3ab551ce, 0xa3bc0074, 0xd4bb30e2,
	0x4adfa541, 0x3dd895d7, 0xa4d1c46d, 0xd3d6f4fb, 0x4369e96a,
	0x346ed9fc, 0xad678846, 0xda60b8d0, 0x44042d73, 0x33031de5,
	0xaa0a4c5f, 0xdd0d7cc9, 0x5005713c, 0x270241aa, 0xbe0b1010,
	0xc90c2086, 0x5768b525, 0x206f85b3, 0xb966d409, 0xce61e49f,
	0x5edef90e, 0x29d9c998, 0xb0d09822, 0xc7d7a8b4, 0x59b33d17,
	0x2eb40d81, 0xb7bd5c3b, 0xc0ba6cad, 0xedb88320, 0x9abfb3b6,
	0x03b6e20c, 0x74b1d29a, 0xead54739, 0x9dd277af, 0x04db2615,
	0x73dc1683, 0xe3630b12, 0x94643b84, 0x0d6d6a3e, 0x7a6a5aa8,
	0xe40ecf0b, 0x9309ff9d, 0x0a00ae27, 0x7d079eb1, 0xf00f9344,
	0x8708a3d2, 0x1e01f268, 0x6906c2fe, 0xf762575d, 0x806567cb,
	0x196c3671, 0x6e6b06e7, 0xfed41b76, 0x89d32be0, 0x10da7a5a,
	0x67dd4acc, 0xf9b9df6f, 0x8ebeeff9, 0x17b7be43, 0x60b08ed5,
	0xd6d6a3e8, 0xa1d1937e, 0x38d8c2c4, 0x4fdff252, 0xd1bb67f1,
	0xa6bc5767, 0x3fb506dd, 0x48b2364b, 0xd80d2bda, 0xaf0a1b4c,
	0x36034af6, 0x41047a60, 0xdf60efc3, 0xa867df55, 0x316e8eef,
	0x4669be79, 0xcb61b38c, 0xbc66831a, 0x256fd2a0, 0x5268e236,
	0xcc0c7795, 0xbb0b4703, 0x220216b9, 0x5505262f, 0xc5ba3bbe,
	0xb2bd0b28, 0x2bb45a92, 0x5cb36a04, 0xc2d7ffa7, 0xb5d0cf31,
	0x2cd99e8b, 0x5bdeae1d, 0x9b64c2b0, 0xec63f226, 0x756aa39c,
	0x026d930a, 0x9c0906a9, 0xeb0e363f, 0x72076785, 0x05005713,
	0x95bf4a82, 0xe2b87a14, 0x7bb12bae, 0x0cb61b38, 0x92d28e9b,
	0xe5d5be0d, 0x7cdcefb7, 0x0bdbdf21, 0x86d3d2d4, 0xf1d4e242,
	0x68ddb3f8, 0x1fda836e, 0x81be16cd, 0xf6b9265b, 0x6fb077e1,
	0x18b74777, 0x88085ae6, 0xff0f6a70, 0x66063bca, 0x11010b5c,
	0x8f659eff, 0xf862ae69, 0x616bffd3, 0x166ccf45, 0xa00ae278,
	0xd70dd2ee, 0x4e048354, 0x3903b3c2, 0xa7672661, 0xd06016f7,
	0x4969474d, 0x3e6e77db, 0xaed16a4a, 0xd9d65adc, 0x40df0b66,
	0x37d83bf0, 0xa9bcae53, 0xdebb9ec5, 0x47b2cf7f, 0x30b5ffe9,
	0xbdbdf21c, 0xcabac28a, 0x53b39330, 0x24b4a3a6, 0xbad03605,
	0xcdd70693, 0x54de5729, 0x23d967bf, 0xb3667a2e, 0xc4614ab8,
	0x5d681b02, 0x2a6f2b94, 0xb40bbe37, 0xc30c8ea1, 0x5a05df1b,
	0x2d02ef8d
};

/* Return a 32-bit CRC of the contents of the buffer. */
static U32 wt_GenCRC32(const U8* s, U32 len)
{
	U32 i;
	U32 crc32val = 0;

	for (i = 0; i < len; i++) 
	{
		crc32val = crc32_tab[(crc32val ^ s[i]) & 0xff] ^ (crc32val >> 8);
	}
	return crc32val;
}

static char* wt_Process_Q_Message(char* primarykey, char* head, char* pubkey, unsigned int* output_len)
{
	U32 i, length, crc32, version = 0;
	sqlite3 *db;
	U8 hexPK[67];
	U8 newhead[89];
	char* message_b64 = NULL;

	for(i=0; i<44; i++) newhead[i] = head[44 + i];
	for(i=0; i<44; i++) newhead[44 + i] = head[i];
	newhead[88] = '#';
	crc32 = wt_GenCRC32(newhead, 89);

	wt_Raw2HexString(pubkey, 33, hexPK, NULL);
	int rc = sqlite3_open_v2("wochat.db", &db, SQLITE_OPEN_READONLY, NULL);
	if (rc == SQLITE_OK) 
	{
		sqlite3_stmt* stmt = NULL;
		char sql[256] = { 0 };
		sprintf(sql, "SELECT vv FROM p WHERE pk='%s'",	hexPK);
		rc = sqlite3_prepare_v2(db, (const char*)sql, -1, &stmt, NULL); 
		if (rc == SQLITE_OK)
		{
			rc = sqlite3_step(stmt);
			//fprintf(stdout, "SQL: %s\n", sql);
			if (rc == SQLITE_ROW)
			{
				version = (U32)sqlite3_column_int(stmt, 0);
			}
			//fprintf(stdout, "%d : VER --> %d\n", rc, version);
		}
		sqlite3_finalize(stmt);
	}
	sqlite3_close(db);

	length = 89 + 140;
	message_b64 = malloc(length);
	if(message_b64)
	{
		U8* p;
		U8 Ks[32];
		U8 hash[32];
		U8 msg[32+33+4+4+32];
		U8 nonce[12] = { 0 };
		AES256_ctx ctxAES = { 0 };
		mbedtls_chacha20_context chacha_ctx = { 0 };
		mbedtls_sha256_context ctx = { 0 };

		wt_GenerateRandomeData(Ks, 32);
		wt_AES256_init(&ctxAES, primarykey);
		wt_AES256_encrypt(&ctxAES, 2, msg, Ks);
		memcpy(msg + 32, pubkey, 33);
		p = (U8*)&version; for(i=0; i<4; i++) msg[32 + 33 + i] = p[i];
		p = (U8*)&crc32;   for(i=0; i<4; i++) msg[32 + 33 + 4 + i] = p[i];

		mbedtls_sha256_init(&ctx);
		mbedtls_sha256_starts_ret(&ctx, 0);
		mbedtls_sha256_update_ret(&ctx, msg+32, 33 + 4 + 4);
		mbedtls_sha256_finish_ret(&ctx, hash);
		wt_AES256_encrypt(&ctxAES, 2, msg+32+33+4+4, hash);

		for (i = 0; i < 12; i++) nonce[i] = i;

		mbedtls_chacha20_init(&chacha_ctx);
		mbedtls_chacha20_setkey(&chacha_ctx, Ks);
		mbedtls_chacha20_starts(&chacha_ctx, nonce, 0);
		mbedtls_chacha20_update(&chacha_ctx, 33 + 4 + 4 + 32, (const unsigned char *)(msg+32), msg+32);
		mbedtls_chacha20_free(&chacha_ctx);

		for(i=0; i<89; i++) message_b64[i] = newhead[i];
		i = (U32)wt_b64_encode(msg, 32+33+4+4+32, message_b64 + 89, 140);
		if(i == 140)
		{
			if(output_len) *output_len = length;
			return message_b64;
		}
	}

	return message_b64;
}

static unsigned char wt_SecretKey [32] = {
	0xE2,0x17,0xA7,0xFC,0xEA,0x47,0x0D,0xDD,
	0xFF,0x22,0x61,0xA4,0x85,0x4A,0x46,0x2F,
	0xE7,0xB6,0xB1,0x0D,0x01,0x14,0x15,0xA5,
	0x00,0xA9,0x7C,0xC9,0xB8,0x0F,0x29,0x89
};

#define UT_MIN_PACKET_SIZE	248

static char* wt_Process_T_Message(char* primarykey, char* head, U8* message, U8 length, unsigned int* output_len)
{
	U32 i, crc32, length_b64;
	char* msssage_b64 = NULL;
	char* msg_raw = NULL;
	U8 offset = 0;
	U32 len_org = length + 10;
	U32 length_raw;
	U8 newhead[89];

	for(i=0; i<44; i++) newhead[i] = head[44 + i];
	for(i=0; i<44; i++) newhead[44 + i] = head[i];
	newhead[88] = '@';
	crc32 = wt_GenCRC32(newhead, 89);

	if(len_org < UT_MIN_PACKET_SIZE)
	{
		length_raw = UT_MIN_PACKET_SIZE + 76;
		offset = (U8)(UT_MIN_PACKET_SIZE - len_org);
	}
	else
	{
		offset = 0;
		length_raw = len_org + 76; // if the message is equal or more than 248 bytes, we do not make random data
	}

	msg_raw = malloc(length_raw);
	if(msg_raw)
	{
		U8 i, idx = 0;
		mbedtls_chacha20_context chacha_ctx = { 0 };
		mbedtls_sha256_context ctx = { 0 };
		AES256_ctx ctxAES = { 0 };
		U8 hash[32] = { 0 };
		U8 Ks[32] = { 0 };
		U8 mask[8] = { 0 };
		U8 nonce[12] = { 0 };
		
		wt_GenerateRandomeData(msg_raw + 76, length_raw - 76); // fill the random data

		U8* p = msg_raw + 76 + 4;
		p[0] = 0xE5; p[1] = 0xB7; p[2] = 0xB2; p[3] = 0xE8; p[4] = 0x8E; 
		p[5] = 0xB7; p[6] = 0xE6; p[7] = 0x82; p[8] = 0x89; p[9] = '\n'; 
		p += 10;
		memcpy(p, message + 4, length - 4);

		mbedtls_sha256_init(&ctx);
		mbedtls_sha256_starts_ret(&ctx, 0);
		mbedtls_sha256_update_ret(&ctx, msg_raw + 76, len_org);
		mbedtls_sha256_finish_ret(&ctx, hash);

		wt_GenerateRandomeData(Ks, 32);
		wt_AES256_init(&ctxAES, primarykey);
		wt_AES256_encrypt(&ctxAES, 2, msg_raw, Ks);
		wt_AES256_encrypt(&ctxAES, 2, msg_raw + 32, hash);

		U32 crc32Hash = wt_GenCRC32(msg_raw + 32, 32);
		p = msg_raw;
		p[64] = 1;	p[65] = 'T'; p[66] = idx; p[67] = 'X';
		U32* p32 = (U32*)(p + 68); *p32 = len_org;
		U8* q = (U8*)&crc32; p[72] = q[0]; p[73] = q[1]; p[74] = q[2]; p[75] = q[3];

		q = (U8*)&crc32Hash; for (i = 0; i < 12; i++) p[64 + i] ^= q[i % 4];

		for (i = 0; i < 12; i++) nonce[i] = i;
		mbedtls_chacha20_init(&chacha_ctx);
		mbedtls_chacha20_setkey(&chacha_ctx, Ks);
		mbedtls_chacha20_starts(&chacha_ctx, nonce, 0);
		mbedtls_chacha20_update(&chacha_ctx, length_raw - 32, (const unsigned char *)(msg_raw+32), msg_raw+32);
		mbedtls_chacha20_free(&chacha_ctx);
		
		length_b64 = wt_b64_enc_len(length_raw);
		msssage_b64 = malloc(89 + length_b64);
		if(msssage_b64)
		{
			for(i=0; i<89; i++) msssage_b64[i] = newhead[i];
			wt_b64_encode((const char*)msg_raw, length_raw, (char*)(msssage_b64 + 89), length_b64);
			if(output_len) *output_len = 89 + length_b64;
		}
		free(msg_raw);
	}
	return msssage_b64;
}

static char* wt_GetRobotResponse(char* message, unsigned int length, U32* output_len, U8* stype)
{
	U8 Kp[32];
	U8 Ks[32];
	U8 PubKey[33];
	char pks[33];
	char pkr[33];
	U8 nonce[12] = { 0 };
	AES256_ctx ctxAES = { 0 };
	mbedtls_chacha20_context chacha_ctx = { 0 };
	U32   resonse_length = 0;
	char* response_message = NULL;

	int r0 = wt_b64_decode(message, 44, pks, 33);
	int r1 = wt_b64_decode(message+44, 44, pkr, 33);

	if((r0 != 33) || (r1 != 33) || (pks[0] != 0x02 && pks[0] != 0x03) || (pkr[0] != 0x02 && pkr[0] != 0x03))
		return NULL;

	if(wt_GenPublicKeyFromSecretKey(wt_SecretKey, PubKey) != WT_OK)
		return NULL;

	if(memcmp(pkr, PubKey, 33)) /* this message is not send to me */
		return NULL;

	if(GetKeyFromSecretKeyAndPlubicKey(wt_SecretKey, pks, Kp) != WT_OK)
		return NULL;

	for (U8 i = 0; i < 12; i++) nonce[i] = i;

	if(message[88] == '?' && length == 225)
	{
		U8 msg_raw[32 + 1 + 33 + 4 + 32] = { 0 };
		U8 msg_len = 32 + 1 + 33 + 4 + 32;

		if(wt_b64_decode(message + 89, 136, msg_raw, msg_len) == msg_len)
		{
			U8 hash0[32];
			U8 hash1[32];

			wt_AES256_init(&ctxAES, Kp);
			wt_AES256_decrypt(&ctxAES, 2, Ks, msg_raw);
			mbedtls_chacha20_init(&chacha_ctx);
			mbedtls_chacha20_setkey(&chacha_ctx, Ks);
			mbedtls_chacha20_starts(&chacha_ctx, nonce, 0);
			mbedtls_chacha20_update(&chacha_ctx, 1 + 33 + 4 + 32, (const unsigned char *)(msg_raw+32), msg_raw+32);
			mbedtls_chacha20_free(&chacha_ctx);
			
			wt_AES256_decrypt(&ctxAES, 2, hash0, msg_raw + 32 + 1 + 33 + 4);

			mbedtls_sha256_context ctx = { 0 };
			mbedtls_sha256_init(&ctx);
			mbedtls_sha256_starts_ret(&ctx, 0);
			mbedtls_sha256_update_ret(&ctx, msg_raw+32, 1 + 33 + 4);
			mbedtls_sha256_finish_ret(&ctx, hash1);

			if(msg_raw[32] == 'Q' && (msg_raw[33] == 0x02 || msg_raw[33] == 0x03))
			{
				U32 crc32 = wt_GenCRC32(message, 89);
				if(memcmp(&crc32, msg_raw + 32 + 1 + 33, 4) == 0 && memcmp(hash0, hash1, 32) == 0)
				{
					//fprintf(stdout, "Get Q Message and CRC32 and hash are good!\n");
					resonse_length = 0;
					response_message = wt_Process_Q_Message(Kp, message, msg_raw + 33, &resonse_length);
					if(output_len) *output_len = resonse_length;
					if(stype) *stype = 'M';
					return response_message;
				}
			}
		}
	}
	else if(message[88] == '@' && length >= 521)
	{
		U8 hash0[32];
		U8 hash1[32];
		U32 length_raw = wt_b64_dec_len(length - 89);
		U8* message_raw = (U8*)malloc(length_raw);
		if (message_raw)
		{
			int real_length = wt_b64_decode((const char*)(message + 89), length - 89, (char*)message_raw, length_raw);
			if(real_length > 0)
			{
				wt_AES256_init(&ctxAES, Kp);
				wt_AES256_decrypt(&ctxAES, 2, Ks, message_raw); // get the session key at first
				mbedtls_chacha20_init(&chacha_ctx);
				mbedtls_chacha20_setkey(&chacha_ctx, Ks);
				mbedtls_chacha20_starts(&chacha_ctx, nonce, 0);
				mbedtls_chacha20_update(&chacha_ctx, real_length - 32, (const unsigned char *)(message_raw+32), message_raw+32);
				mbedtls_chacha20_free(&chacha_ctx);

				U32 crc32Hash = wt_GenCRC32(message_raw + 32, 32);
				U8* p = (U8*)&crc32Hash;
				for(U8 i = 0; i < 12; i++) message_raw[64 + i] ^= p[i % 4];
				U8 vs  = message_raw[64];
				U8 tp  = message_raw[65];
				U8 idx = message_raw[66];
				U8 rs  = message_raw[67];
				U32 lenX = *((U32*)(message_raw + 32 + 32 + 4));
				
				U32 crc32 = wt_GenCRC32(message, 89);
				if(memcmp(&crc32, message_raw + 32 + 32 + 4 + 4, 4) == 0)
				{
					wt_AES256_decrypt(&ctxAES, 2, hash0, message_raw + 32);
					mbedtls_sha256_context ctx = { 0 };
					mbedtls_sha256_init(&ctx);
					mbedtls_sha256_starts_ret(&ctx, 0);
					mbedtls_sha256_update_ret(&ctx, message_raw + 76 + idx, lenX);
					mbedtls_sha256_finish_ret(&ctx, hash1);
					if(memcmp(hash0, hash1, 32) == 0)
					{
						//fprintf(stdout, "Really go000000od! %d - %d - %d - %d(%u)!\n", vs, tp, idx, rs, lenX);
						// now we are pretty confirm this message is good
						switch(tp)
						{
						case 'T':
							resonse_length = 0;
							response_message = wt_Process_T_Message(Kp, message, message_raw + 76 + idx, lenX, &resonse_length);
							if(response_message && resonse_length)
							{
								if(output_len) *output_len = resonse_length;
								if(stype) *stype = 'F';
								free(message_raw);
								return response_message;
							}
							break;
						case 'U':
							break;
						default:
							break;
						}
					}
				}
			}
			free(message_raw);
		}
	}
	return NULL;
}

static char send_cmd[8192] = { 0 };

static void wt_ProcessMessage(struct mosq_config *cfg, char* message, unsigned int len)
{
	char* b64_msg = NULL;
	U32  b64_len = 0;
	U8 sendType = 'M';
	char pks[33];
	char topic[67];
	int port = (cfg->port <= 0) ? 1883 : (cfg->port <= 0);

	wt_b64_decode(message, 44, pks, 33);	
	wt_Raw2HexString(pks, 33, topic, NULL);

	b64_msg = wt_GetRobotResponse(message, len, &b64_len, &sendType);
	if(b64_msg && b64_len > 0)
	{
		if(sendType == 'M')
		{
			sprintf(send_cmd, "mosquitto_pub -h %s -p %d -t %s -m \"%s\"",cfg->host, port, topic, b64_msg);
			//fprintf(stdout, "mosquitto_pub -h %s -p %d -t %s -m \"%s\"",cfg->host, port, topic, b64_msg);
			system(send_cmd);
		}
		else if(sendType == 'F')
		{
			FILE* fp;
			U8 hash[32]; 
			U8 hexHash[65] = {0};
			U8 filename[256] = { 0 };

			mbedtls_sha256_context ctx = { 0 };
			mbedtls_sha256_init(&ctx);
			mbedtls_sha256_starts_ret(&ctx, 0);
			mbedtls_sha256_update_ret(&ctx, b64_msg, b64_len);
			mbedtls_sha256_finish_ret(&ctx, hash);
			wt_Raw2HexString(hash, 32, hexHash, NULL);

			if(cfg->dirpath)
				sprintf(filename, "%s/%s", cfg->dirpath, hexHash);
			else
				sprintf(filename, "./%s", hexHash);

			fp = fopen(filename, "w");
			if(fp)
			{
				bool bRet = false;
				if(EOF != fputs((const char*)b64_msg, fp))
				{
					sprintf(send_cmd, "mosquitto_pub -h %s -p %d -t %s -f %s",cfg->host, port, topic, filename);
					bRet = true;
					//fprintf(stdout, "mosquitto_pub -h %s -p %d -t %s -f %s\n",cfg->host, port, topic, filename);
				}
				fclose(fp);
				if(bRet)
					system(send_cmd);
			}
		}
		free(b64_msg);
	}
}

void print_message(struct mosq_config *lcfg, const struct mosquitto_message *message, const mosquitto_property *properties)
{
	char* buf;
	char* msg = (char*)message->payload;
	unsigned int msg_len = (unsigned int)message->payloadlen;

	//fprintf(stdout, "Get %s (%d) bytes\n", msg, message->payloadlen);
	if(msg && msg_len >= 225)
	{
		char pks[33];
		char pkr[33];
		int r0 = wt_b64_decode(msg, 44, pks, 33);
		int r1 = wt_b64_decode(msg + 44, 44, pkr, 33);

		if(33 == r0 && 33 == r1)
		{
			char* buf = malloc(msg_len);
			if(buf)
			{
				pid_t pid;
				memcpy(buf, msg, msg_len);
				pid = fork();
				if(pid == 0) /* this is the child process */
				{
					wt_ProcessMessage(lcfg, buf, msg_len); 
					free(buf);
					exit(0);
				}
				free(buf);
			}
		}
	}
}

/* 03339A1C8FDB6AFF46845E49D110E0400021E16146341858585C2E25CA399C01CA */