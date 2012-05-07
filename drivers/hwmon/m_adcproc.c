/* Copyright (c) 2010-2011, Code Aurora Forum. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 and
 * only version 2 as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 */

#include <linux/kernel.h>

#include <linux/msm_adc.h>

#ifdef CONFIG_LGE_CHARGER_TEMP_SCENARIO
#include "../../lge/include/lg_power_common.h"
#endif

#define KELVINMIL_DEGMIL	273160

#ifdef CONFIG_LGE_CHARGER_TEMP_SCENARIO
const struct adc_map_pt adcmap_batttherm[THERM_LAST] = {
	{1574,	-10},
	{1477,	 -5},
	{946,	 42},
	{933,	 45},
	{901,	 55},
	{896,	 57},
	{889,	 60},
	{878,	 65},
};
#else
static const struct adc_map_pt adcmap_batttherm[] = {
	{2020,	-30},
	{1923,	-20},
	{1796,	-10},
	{1640,	  0},
	{1459,	 10},
	{1260,	 20},
	{1159,	 25},
	{1059,	 30},
	{871,	 40},
	{706,	 50},
	{567,	 60},
	{453,	 70},
	{364,	 80}
};
#endif

static const struct adc_map_pt adcmap_msmtherm[] = {
	{2150,	-30},
	{2107,	-20},
	{2037,	-10},
	{1929,	  0},
	{1776,	 10},
	{1579,	 20},
	{1467,	 25},
	{1349,	 30},
	{1108,	 40},
	{878,	 50},
	{677,	 60},
	{513,	 70},
	{385,	 80},
	{287,	 90},
	{215,	100},
	{186,	110},
	{107,	120}
};

#if 1 // DAISHINKU XO chipset
static const struct adc_map_pt adcmap_ntcg104ef104fb[] = {
	{	439712 	,	-40000	},
	{	409287 	,	-39000	},
	{	381172 	,	-38000	},
	{	355175 	,	-37000	},
	{	331127 	,	-36000	},
	{	308860 	,	-35000	},
	{	288240 	,	-34000	},
	{	269131 	,	-33000	},
	{	251414 	,	-32000	},
	{	234978 	,	-31000	},
	{	219723 	,	-30000	},
	{	205556 	,	-29000	},
	{	192393 	,	-28000	},
	{	180157 	,	-27000	},
	{	168777 	,	-26000	},
	{	158188 	,	-25000	},
	{	148310 	,	-24000	},
	{	139111 	,	-23000	},
	{	130541 	,	-22000	},
	{	122553 	,	-21000	},
	{	115104 	,	-20000	},
	{	108154 	,	-19000	},
	{	101666 	,	-18000	},
	{	95608	,	-17000	},
	{	89948	,	-16000	},
	{	84658	,	-15000	},
	{	79711	,	-14000	},
	{	75083	,	-13000	},
	{	70752	,	-12000	},
	{	66697	,	-11000	},
	{	62899	,	-10000	},
	{	59334	,	-9000	},
	{	55993	,	-8000	},
	{	52860	,	-7000	},
	{	49921	,	-6000	},
	{	47163	,	-5000	},
	{	44577	,	-4000	},
	{	42148	,	-3000	},
	{	39865	,	-2000	},
	{	37719	,	-1000	},
	{	35701	,	0	},
	{	33801	,	1000	},
	{	32012	,	2000	},
	{	30329	,	3000	},
	{	28743	,	4000	},
	{	27250	,	5000	},
	{	25843	,	6000	},
	{	24516	,	7000	},
	{	23265	,	8000	},
	{	22085	,	9000	},
	{	20971	,	10000	},
	{	19920	,	11000	},
	{	18927	,	12000	},
	{	17989	,	13000	},
	{	17103	,	14000	},
	{	16265	,	15000	},
	{	15473	,	16000	},
	{	14723	,	17000	},
	{	14014	,	18000	},
	{	13343	,	19000	},
	{	12708	,	20000	},
	{	12107	,	21000	},
	{	11537	,	22000	},
	{	10997	,	23000	},
	{	10485	,	24000	},
	{	10000	,	25000	},
	{	9540	,	26000	},
	{	9103	,	27000	},
	{	8689	,	28000	},
	{	8296	,	29000	},
	{	7922	,	30000	},
	{	7568	,	31000	},
	{	7231	,	32000	},
	{	6910	,	33000	},
	{	6606	,	34000	},
	{	6317	,	35000	},
	{	6042	,	36000	},
	{	5780	,	37000	},
	{	5531	,	38000	},
	{	5293	,	39000	},
	{	5068	,	40000	},
	{	4853	,	41000	},
	{	4648	,	42000	},
	{	4453	,	43000	},
	{	4268	,	44000	},
	{	4090	,	45000	},
	{	3921	,	46000	},
	{	3760	,	47000	},
	{	3606	,	48000	},
	{	3460	,	49000	},
	{	3320	,	50000	},
	{	3186	,	51000	},
	{	3058	,	52000	},
	{	2937	,	53000	},
	{	2820	,	54000	},
	{	2709	,	55000	},
	{	2603	,	56000	},
	{	2501	,	57000	},
	{	2404	,	58000	},
	{	2311	,	59000	},
	{	2222	,	60000	},
	{	2137	,	61000	},
	{	2056	,	62000	},
	{	1978	,	63000	},
	{	1907	,	64000	},
	{	1832	,	65000	},
	{	1764	,	66000	},
	{	1699	,	67000	},
	{	1636	,	68000	},
	{	1576	,	69000	},
	{	1518	,	70000	},
	{	1463	,	71000	},
	{	1410	,	72000	},
	{	1359	,	73000	},
	{	1310	,	74000	},
	{	1264	,	75000	},
	{	1219	,	76000	},
	{	1176	,	77000	},
	{	1134	,	78000	},
	{	1095	,	79000	},
	{	1057	,	80000	},
	{	1020	,	81000	},
	{	985	,	82000	},
	{	951	,	83000	},
	{	919	,	84000	},
	{	887	,	85000	},
	{	857	,	86000	},
	{	828	,	87000	},
	{	801	,	88000	},
	{	774	,	89000	},
	{	748	,	90000	},
	{	723	,	91000	},
	{	700	,	92000	},
	{	677	,	93000	},
	{	655	,	94000	},
	{	634	,	95000	},
	{	613	,	96000	},
	{	593	,	97000	},
	{	574	,	98000	},
	{	556	,	99000	},
	{	538	,	100000	},
	{	521	,	101000	},
	{	505	,	102000	},
	{	489	,	103000	},
	{	474	,	104000	},
	{	459	,	105000	},
	{	445	,	106000	},
	{	431	,	107000	},
	{	418	,	108000	},
	{	406	,	109000	},
	{	393	,	110000	},
	{	382	,	111000	},
	{	370	,	112000	},
	{	359	,	113000	},
	{	348	,	114000	},
	{	338	,	115000	},
	{	328	,	116000	},
	{	319	,	117000	},
	{	309	,	118000	},
	{	300	,	119000	},
	{	292	,	120000	},
	{	283	,	121000	},
	{	275	,	122000	},
	{	267	,	123000	},
	{	260	,	124000	},
	{	252	,	125000	}
};
#else
static const struct adc_map_pt adcmap_ntcg104ef104fb[] = {
	{696483,	-40960},
	{649148,	-39936},
	{605368,	-38912},
	{564809,	-37888},
	{527215,	-36864},
	{492322,	-35840},
	{460007,	-34816},
	{429982,	-33792},
	{402099,	-32768},
	{376192,	-31744},
	{352075,	-30720},
	{329714,	-29696},
	{308876,	-28672},
	{289480,	-27648},
	{271417,	-26624},
	{254574,	-25600},
	{238903,	-24576},
	{224276,	-23552},
	{210631,	-22528},
	{197896,	-21504},
	{186007,	-20480},
	{174899,	-19456},
	{164521,	-18432},
	{154818,	-17408},
	{145744,	-16384},
	{137265,	-15360},
	{129307,	-14336},
	{121866,	-13312},
	{114896,	-12288},
	{108365,	-11264},
	{102252,	-10240},
	{96499,		-9216},
	{91111,		-8192},
	{86055,		-7168},
	{81308,		-6144},
	{76857,		-5120},
	{72660,		-4096},
	{68722,		-3072},
	{65020,		-2048},
	{61538,		-1024},
	{58261,		0},
	{55177,		1024},
	{52274,		2048},
	{49538,		3072},
	{46962,		4096},
	{44531,		5120},
	{42243,		6144},
	{40083,		7168},
	{38045,		8192},
	{36122,		9216},
	{34308,		10240},
	{32592,		11264},
	{30972,		12288},
	{29442,		13312},
	{27995,		14336},
	{26624,		15360},
	{25333,		16384},
	{24109,		17408},
	{22951,		18432},
	{21854,		19456},
	{20807,		20480},
	{19831,		21504},
	{18899,		22528},
	{18016,		23552},
	{17178,		24576},
	{16384,		25600},
	{15631,		26624},
	{14916,		27648},
	{14237,		28672},
	{13593,		29696},
	{12976,		30720},
	{12400,		31744},
	{11848,		32768},
	{11324,		33792},
	{10825,		34816},
	{10354,		35840},
	{9900,		36864},
	{9471,		37888},
	{9062,		38912},
	{8674,		39936},
	{8306,		40960},
	{7951,		41984},
	{7616,		43008},
	{7296,		44032},
	{6991,		45056},
	{6701,		46080},
	{6424,		47104},
	{6160,		48128},
	{5908,		49152},
	{5667,		50176},
	{5439,		51200},
	{5219,		52224},
	{5010,		53248},
	{4810,		54272},
	{4619,		55296},
	{4440,		56320},
	{4263,		57344},
	{4097,		58368},
	{3938,		59392},
	{3785,		60416},
	{3637,		61440},
	{3501,		62464},
	{3368,		63488},
	{3240,		64512},
	{3118,		65536},
	{2998,		66560},
	{2889,		67584},
	{2782,		68608},
	{2680,		69632},
	{2581,		70656},
	{2490,		71680},
	{2397,		72704},
	{2310,		73728},
	{2227,		74752},
	{2147,		75776},
	{2064,		76800},
	{1998,		77824},
	{1927,		78848},
	{1860,		79872},
	{1795,		80896},
	{1736,		81920},
	{1673,		82944},
	{1615,		83968},
	{1560,		84992},
	{1507,		86016},
	{1456,		87040},
	{1407,		88064},
	{1360,		89088},
	{1314,		90112},
	{1271,		91136},
	{1228,		92160},
	{1189,		93184},
	{1150,		94208},
	{1112,		95232},
	{1076,		96256},
	{1042,		97280},
	{1008,		98304},
	{976,		99328},
	{945,		100352},
	{915,		101376},
	{886,		102400},
	{859,		103424},
	{832,		104448},
	{807,		105472},
	{782,		106496},
	{756,		107520},
	{735,		108544},
	{712,		109568},
	{691,		110592},
	{670,		111616},
	{650,		112640},
	{631,		113664},
	{612,		114688},
	{594,		115712},
	{577,		116736},
	{560,		117760},
	{544,		118784},
	{528,		119808},
	{513,		120832},
	{498,		121856},
	{483,		122880},
	{470,		123904},
	{457,		124928},
	{444,		125952},
	{431,		126976},
	{419,		128000}
};
#endif

static int32_t
	adc_map_linear(const struct adc_map_pt *pts,
		uint32_t tablesize, int32_t input, int64_t *output)
{
	bool descending = 1;
	uint32_t i = 0;

	if ((pts == NULL) || (output == NULL))
		return -EINVAL;

	/* Check if table is descending or ascending */
	if (tablesize > 1) {
		if (pts[0].x < pts[1].x)
			descending = 0;
	}

	while (i < tablesize) {
		if ((descending == 1) && (pts[i].x < input)) {
			/* table entry is less than measured
				value and table is descending, stop */
			break;
		} else if ((descending == 0) &&
				(pts[i].x > input)) {
			/* table entry is greater than measured
				value and table is ascending, stop */
			break;
		} else
			i++;
	}

	if (i == 0)
		*output = pts[0].y;
	else if (i == tablesize)
		*output = pts[tablesize-1].y;
	else {
	/* result is between search_index and search_index-1 */
	/* interpolate linearly */
	*output = (((int32_t) ((pts[i].y - pts[i-1].y)*
			(input - pts[i-1].x))/
			(pts[i].x - pts[i-1].x))+
			pts[i-1].y);
	}

	return 0;
}

int32_t scale_default(int32_t adc_code,
				const struct adc_properties *adc_properties,
				const struct chan_properties *chan_properties,
				struct adc_chan_result *adc_chan_result)
{
	bool negative_rawfromoffset = 0;
	int32_t rawfromoffset = adc_code - chan_properties->adc_graph->offset;

	if (!chan_properties->gain_numerator ||
		!chan_properties->gain_denominator)
		return -EINVAL;

	adc_chan_result->adc_code = adc_code;
	if (rawfromoffset < 0) {
		if (adc_properties->bipolar) {
			rawfromoffset = (rawfromoffset ^ -1) +  1;
			negative_rawfromoffset = 1;
		} else
			rawfromoffset = 0;
	}

	if (rawfromoffset >= 1 << adc_properties->bitresolution)
		rawfromoffset = (1 << adc_properties->bitresolution) - 1;

	adc_chan_result->measurement = (int64_t)rawfromoffset*
					chan_properties->adc_graph->dx*
					chan_properties->gain_denominator;

	/* do_div only perform positive integer division! */
	do_div(adc_chan_result->measurement, chan_properties->adc_graph->dy*
					chan_properties->gain_numerator);

	if (negative_rawfromoffset)
		adc_chan_result->measurement =
		(adc_chan_result->measurement ^ -1) + 1;

	/* Note: adc_chan_result->measurement is in the unit of
	 * adc_properties.adc_reference. For generic channel processing,
	 * channel measurement is a scale/ratio relative to the adc
	 * reference input */
	adc_chan_result->physical = (int32_t) adc_chan_result->measurement;

	return 0;
}

int32_t scale_batt_therm(int32_t adc_code,
				const struct adc_properties *adc_properties,
				const struct chan_properties *chan_properties,
				struct adc_chan_result *adc_chan_result)
{
	scale_default(adc_code, adc_properties, chan_properties,
			adc_chan_result);
	/* convert mV ---> degC using the table */
	return adc_map_linear(
			adcmap_batttherm,
			sizeof(adcmap_batttherm)/sizeof(adcmap_batttherm[0]),
			adc_chan_result->physical,
			&adc_chan_result->physical);
}

int32_t scale_msm_therm(int32_t adc_code,
		const struct adc_properties *adc_properties,
		const struct chan_properties *chan_properties,
		struct adc_chan_result *adc_chan_result)
{
	scale_default(adc_code, adc_properties, chan_properties,
			adc_chan_result);
	/* convert mV ---> degC using the table */
	return adc_map_linear(
			adcmap_msmtherm,
			sizeof(adcmap_msmtherm)/sizeof(adcmap_msmtherm[0]),
			adc_chan_result->physical,
			&adc_chan_result->physical);
}

int32_t scale_pmic_therm(int32_t adc_code,
				const struct adc_properties *adc_properties,
				const struct chan_properties *chan_properties,
				struct adc_chan_result *adc_chan_result)
{
	/* 2mV/K */
	int32_t rawfromoffset = adc_code - chan_properties->adc_graph->offset;

	if (!chan_properties->gain_numerator ||
		!chan_properties->gain_denominator)
		return -EINVAL;

	adc_chan_result->adc_code = adc_code;
	if (rawfromoffset > 0) {
		if (rawfromoffset >= 1 << adc_properties->bitresolution)
			rawfromoffset = (1 << adc_properties->bitresolution)
									- 1;
		adc_chan_result->measurement = (int64_t)rawfromoffset*
					chan_properties->adc_graph->dx*
					chan_properties->gain_denominator*1000;
		do_div(adc_chan_result->measurement,
			chan_properties->adc_graph->dy*
			chan_properties->gain_numerator*2);
	} else {
		adc_chan_result->measurement = 0;
	}
	/* Note: adc_chan_result->measurement is in the unit of
		adc_properties.adc_reference */
	adc_chan_result->physical = (int32_t)adc_chan_result->measurement;
	/* Change to .001 deg C */
	adc_chan_result->physical -= KELVINMIL_DEGMIL;
	adc_chan_result->measurement <<= 1;

	return 0;
}

/* Scales the ADC code to 0.001 degrees C using the map
 * table for the XO thermistor.
 */
int32_t tdkntcgtherm(int32_t adc_code,
			const struct adc_properties *adc_properties,
			const struct chan_properties *chan_properties,
			struct adc_chan_result *adc_chan_result)
{
	int32_t offset = chan_properties->adc_graph->offset,
		dy = chan_properties->adc_graph->dy,
		dx = chan_properties->adc_graph->dx,
		fullscale_calibrated_adc_code;

	uint32_t rt_r25;
	uint32_t num1, num2, denom;

	adc_chan_result->adc_code = adc_code;
	fullscale_calibrated_adc_code = dy + offset;
	/* The above is a short cut in math that would reduce a lot of
	   computation whereas the below expression
		(adc_properties->adc_reference*dy+dx*offset+(dx>>1))/dx
	   is a more generic formula when the 2 reference voltages are
	   different than 0 and full scale voltage. */

	if ((dy == 0) || (dx == 0) ||
			(offset >= fullscale_calibrated_adc_code)) {
		return -EINVAL;
	} else {
		if (adc_code >= fullscale_calibrated_adc_code) {
			rt_r25 = (uint32_t)-1;
		} else if (adc_code <= offset) {
			rt_r25 = 0;
		} else {
	/* The formula used is (adc_code of current reading - offset)/
	 * (the calibrated fullscale adc code - adc_code of current reading).
	 * For this channel, at this time, chan_properties->gain_numerator =
	 * chan_properties->gain_denominator = 1, so no need to incorporate
	 * into the formula even though we could and multiply/divide by 1
	 * which yields the same result but expensive on computation. */
		num1 = (adc_code - offset) << 14;
		num2 = (fullscale_calibrated_adc_code - adc_code) >> 1;
		denom = fullscale_calibrated_adc_code - adc_code;

			if ((int)denom <= 0)
				rt_r25 = 0x7FFFFFFF;
			else
				rt_r25 = (num1 + num2) / denom;
		}

		if (rt_r25 > 0x7FFFFFFF)
			rt_r25 = 0x7FFFFFFF;

		adc_map_linear(adcmap_ntcg104ef104fb,
		sizeof(adcmap_ntcg104ef104fb)/sizeof(adcmap_ntcg104ef104fb[0]),
		(int32_t)rt_r25, &adc_chan_result->physical);
	}

	return 0;
}

int32_t scale_xtern_chgr_cur(int32_t adc_code,
			const struct adc_properties *adc_properties,
			const struct chan_properties *chan_properties,
			struct adc_chan_result *adc_chan_result)
{
	int32_t rawfromoffset = adc_code - chan_properties->adc_graph->offset;

	if (!chan_properties->gain_numerator ||
		!chan_properties->gain_denominator)
		return -EINVAL;

	adc_chan_result->adc_code = adc_code;
	if (rawfromoffset > 0) {
		if (rawfromoffset >= 1 << adc_properties->bitresolution)
			rawfromoffset = (1 << adc_properties->bitresolution)
									- 1;
		adc_chan_result->measurement = ((int64_t)rawfromoffset * 5)*
						chan_properties->adc_graph->dx*
					chan_properties->gain_denominator;
		do_div(adc_chan_result->measurement,
					chan_properties->adc_graph->dy*
					chan_properties->gain_numerator);
	} else {
		adc_chan_result->measurement = 0;
	}
	adc_chan_result->physical = (int32_t) adc_chan_result->measurement;

	return 0;
}
