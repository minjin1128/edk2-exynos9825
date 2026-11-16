/* SPDX-License-Identifier: MIT */
#ifndef N976N_DXE_PROBE_H
#define N976N_DXE_PROBE_H
#define N976N_DXE_INFO_VERSION 4
#define N976N_DXE_INFO_SIZE 216
#define N976N_DXE_REPORT_SIZE 5888
#define N976N_DXE_REPORT_MAGIC 0x4458453133524550
#define N976N_DXE_COMPLETE_MAGIC 0x4458453133444F4E
#define N976N_DXE_HEAP_GUARD 0x4845415031324752
#define N976N_DXE_STACK_GUARD 0xA55AA55AA55AA55A
#define N976N_DXE_CHECKS_ALL 0xFF
#define N976N_DXE_EVENT_ENTER 20
#define N976N_DXE_EVENT_STAGE 21
#define N976N_DXE_EVENT_FINAL 22
#define N976N_DXE_EVENT_ASSERT 23
#define N976N_DXE_INFO_GUID {0xa678323c,0x14d5,0x49f2,{0x96,0x5e,0x38,0x7a,0x12,0x32,0x44,0x58}}
#define N976N_DXE_CORE_GUID {0xd6a2cb7f,0x6a18,0x4e2f,{0xb4,0x3b,0x99,0x20,0xa7,0x33,0x70,0x0a}}
#define DXE_OFF_MAGIC 0
#define DXE_OFF_SIZE 8
#define DXE_OFF_CHECKS 16
#define DXE_OFF_STATUS 24
#define DXE_OFF_STAGE 32
#define DXE_OFF_ERROR 40
#define DXE_OFF_SYSTEM_TABLE 48
#define DXE_OFF_BOOT_SERVICES 56
#define DXE_OFF_DXE_IMAGE 64
#define DXE_OFF_HOB_LIST 72
#define DXE_OFF_HEAP_BASE 80
#define DXE_OFF_HEAP_END 88
#define DXE_OFF_PAGE_ADDRESS 96
#define DXE_OFF_PAGE_STATUS 104
#define DXE_OFF_PAGE_FREE_STATUS 112
#define DXE_OFF_POOL_ADDRESS 120
#define DXE_OFF_POOL_STATUS 128
#define DXE_OFF_POOL_FREE_STATUS 136
#define DXE_OFF_MAP_STATUS 144
#define DXE_OFF_MAP_SIZE 152
#define DXE_OFF_MAP_COUNT 160
#define DXE_OFF_MAP_KEY 168
#define DXE_OFF_PROTOCOL_INSTALL_STATUS 176
#define DXE_OFF_PROTOCOL_LOCATE_STATUS 184
#define DXE_OFF_PROTOCOL_REMOVE_STATUS 192
#define DXE_OFF_PROTOCOL_FOUND 200
#define DXE_OFF_SCTLR 208
#define DXE_OFF_GUARD_CHECKS 216
#define DXE_OFF_ASSERT_LINE 224
#define DXE_OFF_COMPLETE 232
#define DXE_OFF_MAP_BUFFER 240
#define DXE_OFF_MAP_DESCRIPTOR_SIZE 248
#define N976N_DXE_EVENT_DRIVER_PROGRESS 30
#define N976N_DXE_EVENT_DRIVER_FINAL 31
#define N976N_DXE_EVENT_DRIVER_FAILED 32
#define N976N_DXE_EVENT_MAP_DRIVER 40
#define N976N_DXE_MAP_MAGIC 0x53454331334D4150
#define N976N_DXE_MAP_SIZE 64
#define N976N_DXE_DRIVER_CHECKS_ALL 0xFF
#define N976N_DXE_DRIVER_COMPLETE 0x4452563133444F4E
#define N976N_DXE_DRIVER_FILE_GUID {0x87b4921d,0x0f98,0x45cd,{0x97,0x81,0xff,0x8e,0x1e,0x1e,0xe4,0x13}}
#define N976N_DXE_COMPLETION_GUID {0x9a12d835,0x2041,0x4c76,{0xaf,0xc2,0x71,0x30,0x02,0x82,0x2a,0x13}}
#define DXE_OFF_FP_CPACR_BEFORE 256
#define DXE_OFF_FP_CPACR_AFTER 264
#define DXE_OFF_FP_CHECKS 272
#define DXE_OFF_FP_STATUS 280
#define DXE_OFF_FP_OBSERVED0 288
#define DXE_OFF_FP_OBSERVED1 296
#define DXE_OFF_FP_EXPECTED0 304
#define DXE_OFF_FP_EXPECTED1 312
#define DXE_OFF_DRIVER_CHECKS 320
#define DXE_OFF_DRIVER_STATUS 328
#define DXE_OFF_DISPATCH_NO_ARCH_COUNT 336
#define DXE_OFF_DRIVER_ENTRY_COUNT 344
#define DXE_OFF_DRIVER_RETURNED 352
#define DXE_OFF_DRIVER_IMAGE 360
#define DXE_OFF_DRIVER_IMAGE_SIZE 368
#define DXE_OFF_DRIVER_ENTRY 376
#define DXE_OFF_DRIVER_TEXT_BASE 384
#define DXE_OFF_DRIVER_TEXT_END 392
#define DXE_OFF_DRIVER_HANDLE 400
#define DXE_OFF_DISPATCH_BEGIN_COUNT 408
#define DXE_OFF_DRIVER_EVENT_COUNT 416
#define DXE_OFF_DRIVER_EVENT_CREATE_STATUS 424
#define DXE_OFF_DRIVER_EVENT_SIGNAL_STATUS 432
#define DXE_OFF_DRIVER_EVENT_CLOSE_STATUS 440
#define DXE_OFF_DRIVER_PROTOCOL_STATUS 448
#define DXE_OFF_DRIVER_PROTOCOL_ADDRESS 456
#define DXE_OFF_DRIVER_LOADED_IMAGE_STATUS 464
#define DXE_OFF_DRIVER_MAP_STATUS 472
#define DXE_OFF_DRIVER_MAP_COUNT 480
#define DXE_OFF_DRIVER_RETURN_STATUS 488
#define DXE_OFF_DRIVER_COMPLETE 496
#define DXE_OFF_DEBUG_TABLE 504
#define N976N_DXE_EVENT_GOP_PROGRESS 50
#define N976N_DXE_EVENT_GOP_FINAL 51
#define N976N_DXE_EVENT_GOP_FAILED 52
#define N976N_DXE_EVENT_FB_FAILED 53
#define N976N_FB_INFO_MAGIC 0x46423134494E464F
#define N976N_FB_INFO_VERSION 1
#define N976N_FB_INFO_SIZE 128
#define N976N_FB_INFO_FLAGS 0xFF
#define N976N_FB_INFO_GUID {0x33e18a9f,0x7f67,0x48b8,{0xa1,0x1b,0x14,0x96,0x76,0x4e,0x46,0x42}}
#define N976N_GOP_PATH_GUID {0x8caa976e,0x032a,0x4e51,{0xb5,0xa2,0x4e,0x39,0x37,0x36,0x14,0x47}}
#define N976N_GOP_CHECKS_ALL 0xFF
#define N976N_GOP_COMPLETE 0x474F503134444F4E
#define DXE_OFF_FB_RAW 512
#define DXE_OFF_FB_CHECKS 512
#define DXE_OFF_FB_STATUS 520
#define DXE_OFF_FB_ERROR 528
#define DXE_OFF_FB_INFO 768
#define DXE_OFF_GOP 1024
#define DXE_OFF_GOP_CHECKS 1024
#define DXE_OFF_GOP_STATUS 1032
#define DXE_OFF_GOP_ERROR 1040
#define DXE_OFF_GOP_STAGE 1048
#define DXE_OFF_GOP_PROTOCOL 1056
#define DXE_OFF_GOP_HANDLE 1064
#define DXE_OFF_GOP_INFO 1072
#define DXE_OFF_GOP_MODE 1080
#define DXE_OFF_GOP_FRAME_BUFFER_BASE 1088
#define DXE_OFF_GOP_FRAME_BUFFER_SIZE 1096
#define DXE_OFF_GOP_WIDTH 1104
#define DXE_OFF_GOP_HEIGHT 1112
#define DXE_OFF_GOP_PITCH_BYTES 1120
#define DXE_OFF_GOP_PIXEL_FORMAT 1128
#define DXE_OFF_GOP_LOCATE_STATUS 1136
#define DXE_OFF_GOP_QUERY_STATUS 1144
#define DXE_OFF_GOP_QUERY_FREE_STATUS 1152
#define DXE_OFF_GOP_SET_MODE_STATUS 1160
#define DXE_OFF_GOP_FILL_STATUS 1168
#define DXE_OFF_GOP_BUFFER_TO_VIDEO_STATUS 1176
#define DXE_OFF_GOP_VIDEO_TO_BUFFER_STATUS 1184
#define DXE_OFF_GOP_VIDEO_TO_VIDEO_STATUS 1192
#define DXE_OFF_GOP_COMPARE_CHECKS 1200
#define DXE_OFF_GOP_NEGATIVE_COUNT 1208
#define DXE_OFF_GOP_OVERLAP_COUNT 1216
#define DXE_OFF_GOP_SWATCH_COUNT 1224
#define DXE_OFF_GOP_INFO_PROTOCOL_STATUS 1232
#define DXE_OFF_GOP_DEVICE_PATH_STATUS 1240
#define DXE_OFF_GOP_DEVICE_PATH_ADDRESS 1248
#define DXE_OFF_GOP_PATTERN_HASH 1256
#define DXE_OFF_GOP_COMPLETE 1264
#define DXE_OFF_GOP_RESERVED 1272
#define N976N_DXE_EVENT_CONSOLE_PROGRESS 60
#define N976N_DXE_EVENT_CONSOLE_FINAL 61
#define N976N_DXE_EVENT_CONSOLE_FAILED 62
#define N976N_CONSOLE_CHECKS_ALL 0xFF
#define N976N_CONSOLE_COMPLETE 0x434F4E3135444F4E
#define DXE_OFF_CONSOLE 1280
#define DXE_OFF_CONSOLE_MODULES 1600
#define DXE_OFF_CONSOLE_CHECKS 1280
#define DXE_OFF_CONSOLE_STATUS 1288
#define DXE_OFF_CONSOLE_ERROR 1296
#define DXE_OFF_CONSOLE_STAGE 1304
#define DXE_OFF_CONSOLE_HII_DATABASE 1312
#define DXE_OFF_CONSOLE_HII_FONT 1320
#define DXE_OFF_CONSOLE_DRIVER_BINDING 1328
#define DXE_OFF_CONSOLE_TEXT_OUT 1336
#define DXE_OFF_CONSOLE_CONNECT_STATUS 1344
#define DXE_OFF_CONSOLE_HANDLE_STATUS 1352
#define DXE_OFF_CONSOLE_QUERY_STATUS 1360
#define DXE_OFF_CONSOLE_SET_MODE_STATUS 1368
#define DXE_OFF_CONSOLE_ATTRIBUTE_STATUS 1376
#define DXE_OFF_CONSOLE_CLEAR_STATUS 1384
#define DXE_OFF_CONSOLE_OUTPUT_STATUS 1392
#define DXE_OFF_CONSOLE_CURSOR_STATUS 1400
#define DXE_OFF_CONSOLE_COLUMNS 1408
#define DXE_OFF_CONSOLE_ROWS 1416
#define DXE_OFF_CONSOLE_MODE 1424
#define DXE_OFF_CONSOLE_ATTRIBUTE 1432
#define DXE_OFF_CONSOLE_CURSOR_COLUMN 1440
#define DXE_OFF_CONSOLE_CURSOR_ROW 1448
#define DXE_OFF_CONSOLE_OUTPUT_COUNT 1456
#define DXE_OFF_CONSOLE_CRC_STATUS 1464
#define DXE_OFF_CONSOLE_SYSTEM_TABLE_CRC 1472
#define DXE_OFF_CONSOLE_COMPLETE 1480
#define DXE_OFF_CONSOLE_HII_STATUS 1488
#define DXE_OFF_CONSOLE_FONT_STATUS 1496
#define DXE_OFF_CONSOLE_TEST_STRING_STATUS 1504
#define DXE_OFF_CONSOLE_ENABLE_CURSOR_STATUS 1512
#define DXE_OFF_CONSOLE_IMAGE_COUNT 1520
#define DXE_OFF_CONSOLE_GLYPH_CHECKS 1528
#define N976N_DXE_EVENT_UNMAP_DEMO 41
#define N976N_DXE_EVENT_DEMO_PROGRESS 70
#define N976N_DXE_EVENT_DEMO_FINAL 71
#define N976N_DXE_EVENT_DEMO_FAILED 72
#define N976N_DEMO_CHECKS_ALL 0xFF
#define N976N_DEMO_COMPLETE 0x44454D4F3136444E
#define DXE_OFF_DEMO 1792
#define DXE_OFF_DEMO_MODULE 1952
#define DXE_OFF_DEMO_CHECKS 1792
#define DXE_OFF_DEMO_STATUS 1800
#define DXE_OFF_DEMO_ERROR 1808
#define DXE_OFF_DEMO_STAGE 1816
#define DXE_OFF_DEMO_ENTRY_COUNT 1824
#define DXE_OFF_DEMO_COMPLETE 1832
#define DXE_OFF_DEMO_RETURN_STATUS 1840
#define DXE_OFF_DEMO_RETURN_COUNT 1848
#define DXE_OFF_DEMO_UNMAP_STATUS 1856
#define DXE_OFF_DEMO_UNMAP_COUNT 1864
#define DXE_OFF_DEMO_HANDLE_GONE_STATUS 1872
#define DXE_OFF_DEMO_GOP_STATUS 1880
#define DXE_OFF_DEMO_HII_STATUS 1888
#define DXE_OFF_DEMO_TEXT_STATUS 1896
#define DXE_OFF_DEMO_POOL_STATUS 1904
#define DXE_OFF_DEMO_PAGES_STATUS 1912
#define DXE_OFF_DEMO_MAP_STATUS 1920
#define DXE_OFF_DEMO_MAP_COUNT 1928
#define DXE_OFF_DEMO_FONT_COUNT 1936
#define DXE_OFF_DEMO_FRAME_HASH 1944
#define N976N_EXT_WINDOW_BASE 0x92000000
#define N976N_EXT_WINDOW_SIZE 0x04000000
#define N976N_EXT_USABLE_BASE 0x92001000
#define N976N_EXT_USABLE_SIZE 0x03FFE000
#define N976N_EXT_POLICY_ALL 0xFF
#define N976N_EXT_CHECKS_ALL 0xFF
#define N976N_EXT_COMPLETE 0x4558543137444F4E
#define N976N_EXT_GUARD 0x4558543137475244
#define N976N_DXE_EVENT_EXT_PROGRESS 80
#define N976N_DXE_EVENT_EXT_FINAL 81
#define N976N_DXE_EVENT_EXT_FAILED 82
#define DXE_OFF_EXT 2048
#define DXE_OFF_EXT_CHECKS 2048
#define DXE_OFF_EXT_STATUS 2056
#define DXE_OFF_EXT_ERROR 2064
#define DXE_OFF_EXT_STAGE 2072
#define DXE_OFF_EXT_WINDOW_BASE 2080
#define DXE_OFF_EXT_WINDOW_SIZE 2088
#define DXE_OFF_EXT_USABLE_BASE 2096
#define DXE_OFF_EXT_USABLE_SIZE 2104
#define DXE_OFF_EXT_POLICY_CHECKS 2112
#define DXE_OFF_EXT_POLICY_STATUS 2120
#define DXE_OFF_EXT_REGISTER_STATUS 2128
#define DXE_OFF_EXT_ALLOCATE_STATUS 2136
#define DXE_OFF_EXT_FREE_STATUS 2144
#define DXE_OFF_EXT_MAP_BEFORE_TYPE 2152
#define DXE_OFF_EXT_MAP_DURING_TYPE 2160
#define DXE_OFF_EXT_MAP_AFTER_TYPE 2168
#define DXE_OFF_EXT_WORDS_TESTED 2176
#define DXE_OFF_EXT_PASS_COUNT 2184
#define DXE_OFF_EXT_GUARD_CHECKS 2192
#define DXE_OFF_EXT_MISMATCH_ADDRESS 2200
#define DXE_OFF_EXT_EXPECTED 2208
#define DXE_OFF_EXT_OBSERVED 2216
#define DXE_OFF_EXT_MAP_COUNT_BEFORE 2224
#define DXE_OFF_EXT_MAP_COUNT_DURING 2232
#define DXE_OFF_EXT_MAP_COUNT_AFTER 2240
#define DXE_OFF_EXT_DESCRIPTOR_RESERVE 2248
#define DXE_OFF_EXT_COMPLETE 2256
#define DXE_OFF_EXT_MAP_RECORDS 2264
#define DXE_OFF_EXT_MAP_RECORD_COUNT 2272
#define DXE_OFF_EXT_MAP_RECORD_SIZE 2280
#define DXE_OFF_EXT_REMAINING_FREE_DESCRIPTORS 2288
#define N976N_GENERIC_CHECKS_ALL 0xFF
#define N976N_GENERIC_COMPLETE 0x47454E3139444F4E
#define N976N_GENERIC_PAGE_BYTES 0x00800000
#define N976N_GENERIC_POOL_BYTES 0x00800101
#define N976N_GENERIC_POOL_SPAN 0x00801000
#define N976N_DXE_EVENT_GENERIC_PROGRESS 90
#define N976N_DXE_EVENT_GENERIC_FINAL 91
#define N976N_DXE_EVENT_GENERIC_FAILED 92
#define DXE_OFF_GENERIC 2304
#define DXE_OFF_GENERIC_CHECKS 2304
#define DXE_OFF_GENERIC_STATUS 2312
#define DXE_OFF_GENERIC_ERROR 2320
#define DXE_OFF_GENERIC_STAGE 2328
#define DXE_OFF_GENERIC_COMPLETE 2336
#define DXE_OFF_GENERIC_PAGE_BYTES 2344
#define DXE_OFF_GENERIC_PAGE_COUNT 2352
#define DXE_OFF_GENERIC_POOL_BYTES 2360
#define DXE_OFF_GENERIC_PAGE_ADDRESS0 2368
#define DXE_OFF_GENERIC_PAGE_ADDRESS1 2376
#define DXE_OFF_GENERIC_POOL_ADDRESS0 2384
#define DXE_OFF_GENERIC_POOL_ADDRESS1 2392
#define DXE_OFF_GENERIC_POOL_BASE0 2400
#define DXE_OFF_GENERIC_POOL_BASE1 2408
#define DXE_OFF_GENERIC_POOL_SPAN0 2416
#define DXE_OFF_GENERIC_POOL_SPAN1 2424
#define DXE_OFF_GENERIC_PAGE_ALLOC_STATUS0 2432
#define DXE_OFF_GENERIC_PAGE_ALLOC_STATUS1 2440
#define DXE_OFF_GENERIC_PAGE_FREE_STATUS0 2448
#define DXE_OFF_GENERIC_PAGE_FREE_STATUS1 2456
#define DXE_OFF_GENERIC_POOL_ALLOC_STATUS0 2464
#define DXE_OFF_GENERIC_POOL_ALLOC_STATUS1 2472
#define DXE_OFF_GENERIC_POOL_FREE_STATUS0 2480
#define DXE_OFF_GENERIC_POOL_FREE_STATUS1 2488
#define DXE_OFF_GENERIC_LIVE_CHECKS 2496
#define DXE_OFF_GENERIC_PATTERN_CHECKS 2504
#define DXE_OFF_GENERIC_BYTES_VERIFIED 2512
#define DXE_OFF_GENERIC_GUARD_CHECKS 2520
#define DXE_OFF_GENERIC_MAP_CHECKS 2528
#define DXE_OFF_GENERIC_FINAL_CONVENTIONAL_BYTES 2536
#define DXE_OFF_GENERIC_MAP_RECORDS 2544
#define DXE_OFF_GENERIC_MAP_RECORD_COUNT 2552
#define DXE_OFF_GENERIC_MAP_RECORD_SIZE 2560
#define DXE_OFF_GENERIC_DESCRIPTOR_RESERVE 2568
#define DXE_OFF_GENERIC_REMAINING_FREE_DESCRIPTORS 2576
#define DXE_OFF_GENERIC_MISMATCH_ADDRESS 2584
#define DXE_OFF_GENERIC_EXPECTED 2592
#define DXE_OFF_GENERIC_OBSERVED 2600
#define DXE_OFF_GENERIC_POOL_METADATA_CHECKS 2608
#define DXE_OFF_GENERIC_ALLOCATION_COUNT 2616
#define DXE_OFF_GENERIC_FREE_COUNT 2624
#define DXE_OFF_GENERIC_PAGE_REUSE 2632
#define DXE_OFF_GENERIC_POOL_REUSE 2640
#define DXE_OFF_GENERIC_FINAL_MAP_COUNT 2648
#define DXE_OFF_GENERIC_SCTLR 2656
#define DXE_OFF_GENERIC_CPACR 2664
#define DXE_OFF_GENERIC_SP 2672
#define DXE_OFF_GENERIC_TPL 2680

#define N976N_LIVE_CHECKS_ALL 0xFF
#define N976N_LIVE_COMPLETE 0x4C4956453230444E
#define N976N_LIVE_OPTIONS_MAGIC 0x4C49564532304F50
#define N976N_LIVE_OPTIONS_VERSION 1
#define N976N_LIVE_OPTIONS_SIZE 64
#define N976N_LIVE_MODE 1
#define N976N_DXE_EVENT_LIVE_PROGRESS 100
#define N976N_DXE_EVENT_LIVE_FINAL 101
#define N976N_DXE_EVENT_LIVE_FAILED 102
#define DXE_OFF_LIVE 2816
#define DXE_OFF_LIVE_CHECKS 2816
#define DXE_OFF_LIVE_STATUS 2824
#define DXE_OFF_LIVE_ERROR 2832
#define DXE_OFF_LIVE_STAGE 2840
#define DXE_OFF_LIVE_COMPLETE 2848
#define DXE_OFF_LIVE_SETUP_CHECKS 2856
#define DXE_OFF_LIVE_COUNTER_FREQUENCY 2864
#define DXE_OFF_LIVE_COUNTER_BEFORE 2872
#define DXE_OFF_LIVE_COUNTER_AFTER 2880
#define DXE_OFF_LIVE_COUNTER_DELTA 2888
#define DXE_OFF_LIVE_COUNTER_READ_COUNT 2896
#define DXE_OFF_LIVE_STALL_STATUS 2904
#define DXE_OFF_LIVE_STALL_REQUEST_US 2912
#define DXE_OFF_LIVE_STALL_TICKS 2920
#define DXE_OFF_LIVE_STALL_COUNT 2928
#define DXE_OFF_LIVE_STALL_RECORDS 2936
#define DXE_OFF_LIVE_STALL_RECORD_COUNT 2944
#define DXE_OFF_LIVE_STALL_RECORD_SIZE 2952
#define DXE_OFF_LIVE_CRC_STATUS 2960
#define DXE_OFF_LIVE_CRC_KNOWN 2968
#define DXE_OFF_LIVE_CRC_CHECKS 2976
#define DXE_OFF_LIVE_BS_CRC 2984
#define DXE_OFF_LIVE_ST_CRC 2992
#define DXE_OFF_LIVE_RT_CRC 3000
#define DXE_OFF_LIVE_DS_CRC 3008
#define DXE_OFF_LIVE_DEBUG_CRC 3016
#define DXE_OFF_LIVE_METRONOME_PROTOCOL 3024
#define DXE_OFF_LIVE_METRONOME_INSTALL_STATUS 3032
#define DXE_OFF_LIVE_CRC_FUNCTION 3040
#define DXE_OFF_LIVE_METRONOME_WAIT 3048
#define DXE_OFF_LIVE_TPL_BEFORE 3056
#define DXE_OFF_LIVE_TPL_AFTER 3064
#define DXE_OFF_LIVE_DAIF_BEFORE 3072
#define DXE_OFF_LIVE_DAIF_AFTER 3080
#define DXE_OFF_LIVE_TRANSITION_EVENT 3088
#define DXE_OFF_LIVE_TRANSITION_COUNT 3096
#define DXE_OFF_LIVE_TRANSITION_TPL 3104
#define DXE_OFF_LIVE_TRANSITION_SIGNAL_STATUS 3112
#define DXE_OFF_LIVE_TRANSITION_CLOSE_STATUS 3120
#define DXE_OFF_LIVE_ENTRY_COUNT 3128
#define DXE_OFF_LIVE_RETURN_STATUS 3136
#define DXE_OFF_LIVE_RETURN_COUNT 3144
#define DXE_OFF_LIVE_UNMAP_STATUS 3152
#define DXE_OFF_LIVE_UNMAP_COUNT 3160
#define DXE_OFF_LIVE_HANDLE_GONE_STATUS 3168
#define DXE_OFF_LIVE_PAGE_ALLOC_STATUS 3176
#define DXE_OFF_LIVE_PAGE_FREE_STATUS 3184
#define DXE_OFF_LIVE_PAGE_ADDRESS 3192
#define DXE_OFF_LIVE_PAGE_BYTES 3200
#define DXE_OFF_LIVE_POOL_ALLOC_STATUS 3208
#define DXE_OFF_LIVE_POOL_FREE_STATUS 3216
#define DXE_OFF_LIVE_POOL_ADDRESS 3224
#define DXE_OFF_LIVE_POOL_BYTES 3232
#define DXE_OFF_LIVE_POOL_BASE 3240
#define DXE_OFF_LIVE_POOL_SPAN 3248
#define DXE_OFF_LIVE_EVENT_CREATE_STATUS 3256
#define DXE_OFF_LIVE_EVENT_SIGNAL_STATUS 3264
#define DXE_OFF_LIVE_EVENT_CLOSE_STATUS 3272
#define DXE_OFF_LIVE_EVENT_COUNT 3280
#define DXE_OFF_LIVE_EVENT_TPL 3288
#define DXE_OFF_LIVE_WAIT_EVENT 3296
#define DXE_OFF_LIVE_WAIT_CREATE_STATUS 3304
#define DXE_OFF_LIVE_WAIT_SIGNAL_STATUS 3312
#define DXE_OFF_LIVE_WAIT_STATUS 3320
#define DXE_OFF_LIVE_WAIT_INDEX 3328
#define DXE_OFF_LIVE_WAIT_CLOSE_STATUS 3336
#define DXE_OFF_LIVE_TEXT_STATUS 3344
#define DXE_OFF_LIVE_BYTES_VERIFIED 3352
#define DXE_OFF_LIVE_MAP_RECORDS 3360
#define DXE_OFF_LIVE_MAP_RECORD_COUNT 3368
#define DXE_OFF_LIVE_MAP_RECORD_SIZE 3376
#define DXE_OFF_LIVE_MAP_CHECKS 3384
#define DXE_OFF_LIVE_AUX_PAGES_MAX 3392
#define DXE_OFF_LIVE_AUX_PAGES_FINAL 3400
#define DXE_OFF_LIVE_DESCRIPTOR_RESERVE 3408
#define DXE_OFF_LIVE_REMAINING_FREE_DESCRIPTORS 3416
#define DXE_OFF_LIVE_GUARD_CHECKS 3424
#define DXE_OFF_LIVE_CPACR 3432
#define DXE_OFF_LIVE_SCTLR 3440
#define DXE_OFF_LIVE_SP 3448
#define DXE_OFF_LIVE_MISMATCH_ADDRESS 3456
#define DXE_OFF_LIVE_EXPECTED 3464
#define DXE_OFF_LIVE_OBSERVED 3472
#define DXE_OFF_LIVE_FINAL_TPL 3480
#define DXE_OFF_LIVE_APP_PHASE 3488
#define DXE_OFF_LIVE_PENDING_CHECKS 3496
#define DXE_OFF_LIVE_FINAL_MAP_COUNT 3504
#define DXE_OFF_LIVE_CPU_GUARD_CHECKS 3512
#define DXE_OFF_LIVE_MODULE 3744


#define N976N_VOLUME_CHECKS_ALL 0xFF
#define N976N_VOLUME_COMPLETE 0x564F4C3231444F4E
#define N976N_VOLUME_APP_COMPLETE 0x4150503231444F4E
#define N976N_VOLUME_OPTIONS_MAGIC 0x564F4C32314F5054
#define N976N_DXE_EVENT_VOLUME_PREPARE 110
#define N976N_DXE_EVENT_VOLUME_MAP 111
#define N976N_DXE_EVENT_VOLUME_UNMAP 112
#define N976N_DXE_EVENT_VOLUME_PROGRESS 113
#define N976N_DXE_EVENT_VOLUME_FINAL 114
#define N976N_DXE_EVENT_VOLUME_FAILED 115
#define DXE_OFF_VOLUME 3840
#define DXE_OFF_VOLUME_CHECKS 3840
#define DXE_OFF_VOLUME_STATUS 3848
#define DXE_OFF_VOLUME_ERROR 3856
#define DXE_OFF_VOLUME_STAGE 3864
#define DXE_OFF_VOLUME_COMPLETE 3872
#define DXE_OFF_VOLUME_ACTIVE_MODULE 3880
#define DXE_OFF_VOLUME_DISK_BASE 3888
#define DXE_OFF_VOLUME_DISK_SIZE 3896
#define DXE_OFF_VOLUME_DISK_CRC_BEFORE 3904
#define DXE_OFF_VOLUME_DISK_CRC_AFTER 3912
#define DXE_OFF_VOLUME_VOLUME_HANDLE 3920
#define DXE_OFF_VOLUME_BLOCK_IO 3928
#define DXE_OFF_VOLUME_DISK_IO 3936
#define DXE_OFF_VOLUME_FILE_SYSTEM 3944
#define DXE_OFF_VOLUME_DEVICE_PATH 3952
#define DXE_OFF_VOLUME_FILE_PATH 3960
#define DXE_OFF_VOLUME_INSTALL_STATUS 3968
#define DXE_OFF_VOLUME_CONNECT_STATUS 3976
#define DXE_OFF_VOLUME_OPEN_VOLUME_STATUS 3984
#define DXE_OFF_VOLUME_OPEN_FILE_STATUS 3992
#define DXE_OFF_VOLUME_READ_STATUS 4000
#define DXE_OFF_VOLUME_READ_BYTES 4008
#define DXE_OFF_VOLUME_READ_COMPARE 4016
#define DXE_OFF_VOLUME_FILE_CLOSE_STATUS 4024
#define DXE_OFF_VOLUME_ROOT_CLOSE_STATUS 4032
#define DXE_OFF_VOLUME_READ_ONLY_STATUS 4040
#define DXE_OFF_VOLUME_BLOCK_READ_COUNT 4048
#define DXE_OFF_VOLUME_DISK_READ_COUNT 4056
#define DXE_OFF_VOLUME_READ_BYTES_TOTAL 4064
#define DXE_OFF_VOLUME_WRITE_ATTEMPTS 4072
#define DXE_OFF_VOLUME_REJECTED_READS 4080
#define DXE_OFF_VOLUME_ENTRY_COUNT 4088
#define DXE_OFF_VOLUME_RETURN_STATUS 4096
#define DXE_OFF_VOLUME_RETURN_COUNT 4104
#define DXE_OFF_VOLUME_UNMAP_STATUS 4112
#define DXE_OFF_VOLUME_UNMAP_COUNT 4120
#define DXE_OFF_VOLUME_HANDLE_GONE_STATUS 4128
#define DXE_OFF_VOLUME_TEXT_STATUS 4136
#define DXE_OFF_VOLUME_RELOC_VALUE 4144
#define DXE_OFF_VOLUME_RELOC_POINTER 4152
#define DXE_OFF_VOLUME_DATA_VALUE 4160
#define DXE_OFF_VOLUME_BSS_VALUE 4168
#define DXE_OFF_VOLUME_APP_CHECKS 4176
#define DXE_OFF_VOLUME_APP_STATUS 4184
#define DXE_OFF_VOLUME_APP_COMPLETE 4192
#define DXE_OFF_VOLUME_MAP_RECORDS 4200
#define DXE_OFF_VOLUME_MAP_RECORD_COUNT 4208
#define DXE_OFF_VOLUME_MAP_RECORD_SIZE 4216
#define DXE_OFF_VOLUME_MAP_CHECKS 4224
#define DXE_OFF_VOLUME_GUARD_CHECKS 4232
#define DXE_OFF_VOLUME_CRC_CHECKS 4240
#define DXE_OFF_VOLUME_DESCRIPTOR_RESERVE 4248
#define DXE_OFF_VOLUME_REMAINING_FREE_DESCRIPTORS 4256
#define DXE_OFF_VOLUME_FINAL_TPL 4264
#define DXE_OFF_VOLUME_DEBUG_COUNT 4272
#define DXE_OFF_VOLUME_LOADED_DEVICE_HANDLE 4280
#define DXE_OFF_VOLUME_LOADED_FILE_PATH 4288
#define DXE_OFF_VOLUME_PAYLOAD_LOAD_SOURCE 4296
#define DXE_OFF_VOLUME_PAYLOAD_LOAD_SIZE 4304
#define DXE_OFF_VOLUME_CODE_BYTES 4312
#define DXE_OFF_VOLUME_AUX_BYTES 4320
#define DXE_OFF_VOLUME_FINAL_CONVENTIONAL_BYTES 4328
#define DXE_OFF_VOLUME_PATH_CHECK 4336
#define DXE_OFF_VOLUME_MODULE_CHECKS 4344
#define DXE_OFF_VOLUME_DRIVER_BINDING 4352
#define DXE_OFF_VOLUME_DRIVER_BINDING_COUNT 4360
#define DXE_OFF_VOLUME_DISK_STATUS 4368
#define DXE_OFF_VOLUME_CPU_CHECKS 4376
#define DXE_OFF_VOLUME_SCTLR 4384
#define DXE_OFF_VOLUME_CPACR 4392
#define DXE_OFF_VOLUME_SP 4400
#define DXE_OFF_VOLUME_BLOCK_NEGATIVE_CHECKS 4408
#define DXE_OFF_VOLUME_DISK_NEGATIVE_CHECKS 4416
#define DXE_OFF_VOLUME_FILE_INFO_SIZE 4424
#define DXE_OFF_VOLUME_FILE_SIZE 4432
#define DXE_OFF_VOLUME_MISSING_STATUS 4440
#define DXE_OFF_VOLUME_PENDING_CHECKS 4448
#define DXE_OFF_VOLUME_READ_BUFFER 4456
#define DXE_OFF_VOLUME_READ_BUFFER_SIZE 4464
#define DXE_OFF_VOLUME_DISK_UNCHANGED 4472
#define DXE_OFF_VOLUME_MODULE 4480

/* SEC28 app admission/lifetime ABI. Existing 4864 bytes stay byte-for-byte laid out. */
#define N976N_CHAIN_COMPLETE 0x43484E3232444F4E
#define N976N_CHAIN_CHECKS_ALL 0xFF
#define N976N_IMAGE_MAP_MAGIC 0x53454332324D4150
#define N976N_IMAGE_MAP_SIZE 224
#define N976N_IMAGE_MAX_RANGES 8
#define N976N_IMAGE_MAX_SECTIONS 16
#define N976N_IMAGE_MAX_SIZE 0x400000
#define N976N_IMAGE_REGISTRY_CAPACITY 8
#define N976N_DXE_EVENT_CHAIN_MAP 120
#define N976N_DXE_EVENT_CHAIN_UNMAP 121
#define N976N_DXE_EVENT_CHAIN_PROGRESS 122
#define N976N_DXE_EVENT_CHAIN_FINAL 123
#define N976N_DXE_EVENT_CHAIN_FAILED 124
#define N976N_DXE_EVENT_BOOT_PREPARE 130
#define N976N_DXE_EVENT_BOOT_PROGRESS 131
#define N976N_DXE_EVENT_BOOT_FINAL 132
#define N976N_DXE_EVENT_BOOT_FAILED 133
#define N976N_BOOT_COMPLETE 0x5345433237424F4F
#define N976N_BOOT_CHECKS_ALL 0xFF
#define N976N_BOOT_EXPECTED_STATUS 0
#define N976N_BOOT_ALLOCATION_STATUS 0x800000000000000E
#define DXE_OFF_BOOT 5376
#define DXE_OFF_BOOT_CHECKS 5376
#define DXE_OFF_BOOT_STATUS 5384
#define DXE_OFF_BOOT_ERROR 5392
#define DXE_OFF_BOOT_STAGE 5400
#define DXE_OFF_BOOT_COMPLETE 5408
#define DXE_OFF_BOOT_PAYLOAD_BASE 5416
#define DXE_OFF_BOOT_PAYLOAD_SIZE 5424
#define DXE_OFF_BOOT_PAYLOAD_CRC 5432
#define DXE_OFF_BOOT_IMAGE_BASE 5440
#define DXE_OFF_BOOT_IMAGE_SIZE 5448
#define DXE_OFF_BOOT_ENTRY 5456
#define DXE_OFF_BOOT_HANDLE 5464
#define DXE_OFF_BOOT_LOAD_STATUS 5472
#define DXE_OFF_BOOT_START_STATUS 5480
#define DXE_OFF_BOOT_UNLOAD_STATUS 5488
#define DXE_OFF_BOOT_GET_VARIABLE_COUNT 5496
#define DXE_OFF_BOOT_SERVICE_ID 5504
#define DXE_OFF_BOOT_CALLER_PC 5512
#define DXE_OFF_BOOT_ORIGINAL_STATUS 5520
#define DXE_OFF_BOOT_ACTIVE_COUNT 5528
#define DXE_OFF_BOOT_MAP_CHECKS 5536
#define DXE_OFF_BOOT_GUARD_CHECKS 5544
#define DXE_OFF_BOOT_CPU_CHECKS 5552
#define DXE_OFF_BOOT_FINAL_TPL 5560
#define DXE_OFF_BOOT_SOURCE_COPY 5568
#define DXE_OFF_BOOT_SOURCE_COPY_SIZE 5576
#define DXE_OFF_BOOT_LOAD_COUNT_BEFORE 5584
#define DXE_OFF_BOOT_UNMAP_COUNT_BEFORE 5592
#define DXE_OFF_BOOT_VARIABLE_CODE 5600
#define DXE_OFF_BOOT_VENDOR_GUID_MATCH 5608
#define DXE_OFF_BOOT_LOAD_COUNT_AFTER 5616
#define DXE_OFF_BOOT_UNMAP_COUNT_AFTER 5624
#define DXE_OFF_BOOT_RETURNED 5632
#define DXE_OFF_BOOT_ALLOCATION_STATUS 5776
#define DXE_OFF_BOOT_MEMORY_MAP_STATUS 5792
#define DXE_OFF_BOOT_ARCHITECTURE_CHECKS 5824
#define DXE_OFF_BOOT_PMU_CHECKS 5872
#define DXE_OFF_CHAIN 4864
#define DXE_OFF_CHAIN_CHECKS 4864
#define DXE_OFF_CHAIN_STATUS 4872
#define DXE_OFF_CHAIN_ERROR 4880
#define DXE_OFF_CHAIN_STAGE 4888
#define DXE_OFF_CHAIN_COMPLETE 4896
#define DXE_OFF_CHAIN_LOAD_COUNT 4904
#define DXE_OFF_CHAIN_START_COUNT 4912
#define DXE_OFF_CHAIN_UNLOAD_COUNT 4920
#define DXE_OFF_CHAIN_MAP_COUNT 4928
#define DXE_OFF_CHAIN_UNMAP_COUNT 4936
#define DXE_OFF_CHAIN_REJECT_COUNT 4944
#define DXE_OFF_CHAIN_ROLLBACK_COUNT 4952
#define DXE_OFF_CHAIN_ACTIVE_COUNT 4960
#define DXE_OFF_CHAIN_PEAK_COUNT 4968
#define DXE_OFF_CHAIN_RETURN_COUNT 4976
#define DXE_OFF_CHAIN_EXIT_COUNT 4984
#define DXE_OFF_CHAIN_PRESTART_UNLOAD_COUNT 4992
#define DXE_OFF_CHAIN_CHAIN_STATUS 5000
#define DXE_OFF_CHAIN_MAP_CHECKS 5008
#define DXE_OFF_CHAIN_GUARD_CHECKS 5016
#define DXE_OFF_CHAIN_CPU_CHECKS 5024
#define DXE_OFF_CHAIN_FINAL_TPL 5032
#define DXE_OFF_CHAIN_REGISTRY_ADDRESS 5040
#define DXE_OFF_CHAIN_RECORD_SIZE 5048
#define DXE_OFF_CHAIN_CAPACITY 5056
#define DXE_OFF_CHAIN_SOURCE_READ_COUNT 5064
#define DXE_OFF_CHAIN_HOOK_LOAD_COUNT 5072
#define DXE_OFF_CHAIN_HOOK_UNLOAD_COUNT 5080
#define DXE_OFF_CHAIN_PARENT_INTACT_COUNT 5088
#define DXE_OFF_CHAIN_RAW_REGISTRY_ADDRESS 5096
#define DXE_OFF_CHAIN_RAW_RECORD_SIZE 5104
#define DXE_OFF_CHAIN_RAW_CAPACITY 5112
#define DXE_OFF_CHAIN_RAW_ACTIVE_COUNT 5120
#define DXE_OFF_CHAIN_RAW_MAP_COUNT 5128
#define DXE_OFF_CHAIN_RAW_UNMAP_COUNT 5136
#define DXE_OFF_CHAIN_RAW_REJECT_COUNT 5144
#define DXE_OFF_CHAIN_RAW_FATAL 5152
#define DXE_OFF_CHAIN_RAW_CHECKS 5160
#define DXE_OFF_CHAIN_STANDARD_STATUS 5168
#define DXE_OFF_CHAIN_EXIT_STATUS 5176
#define DXE_OFF_CHAIN_UNLOAD_STATUS 5184
#define DXE_OFF_CHAIN_MALFORMED_STATUS 5192
#define DXE_OFF_CHAIN_UNSUPPORTED_STATUS 5200
#define DXE_OFF_CHAIN_EXHAUSTION_STATUS 5208
#define DXE_OFF_CHAIN_FINAL_CONVENTIONAL_BYTES 5216
#define DXE_OFF_CHAIN_FINAL_MAP_COUNT 5224
#define DXE_OFF_CHAIN_DISK_CRC_BEFORE 5232
#define DXE_OFF_CHAIN_DISK_CRC_AFTER 5240

#ifndef __ASSEMBLER__
#ifdef N976N_EDK2_MODULE
#include <Base.h>
typedef UINT64 dxe_u64;
typedef UINT16 dxe_u16;
#else
#include <stdint.h>
typedef uint64_t dxe_u64;
typedef uint16_t dxe_u16;
#endif
typedef struct {
  dxe_u64 Magic, Size, Version, Flags, Base, VisibleBytes, Width, Height;
  dxe_u64 PitchBytes, PixelFormat, RedMask, GreenMask, BlueMask, ReservedMask;
  dxe_u64 ReservedByteValue, Reserved;
} N976N_FB_INFO;
typedef struct {
  dxe_u64 Raw[32];
  N976N_FB_INFO Info;
  dxe_u64 Reserved[16];
} N976N_FB_REPORT;
typedef struct {
  dxe_u64 Checks, Status, Error, Stage, Protocol, Handle, Info, Mode, FrameBufferBase, FrameBufferSize, Width, Height, PitchBytes, PixelFormat, LocateStatus, QueryStatus, QueryFreeStatus, SetModeStatus, FillStatus, BufferToVideoStatus, VideoToBufferStatus, VideoToVideoStatus, CompareChecks, NegativeCount, OverlapCount, SwatchCount, InfoProtocolStatus, DevicePathStatus, DevicePathAddress, PatternHash, Complete, Reserved;
} N976N_GOP_REPORT;
typedef struct {
  dxe_u64 Source, SourceSize, ImageBase, ImageSize, Entry, TextBase, TextEnd;
  dxe_u64 Handle, LoadStatus, StartStatus, MapStatus, MapCount;
} N976N_CONSOLE_MODULE;
typedef struct {
  dxe_u64 Checks, Status, Error, Stage, HiiDatabase, HiiFont, DriverBinding, TextOut, ConnectStatus, HandleStatus, QueryStatus, SetModeStatus, AttributeStatus, ClearStatus, OutputStatus, CursorStatus, Columns, Rows, Mode, Attribute, CursorColumn, CursorRow, OutputCount, CrcStatus, SystemTableCrc, Complete, HiiStatus, FontStatus, TestStringStatus, EnableCursorStatus, ImageCount, GlyphChecks;
  dxe_u64 Reserved[8];
  N976N_CONSOLE_MODULE Module[2]; /* HII first, GraphicsConsole second. */
} N976N_CONSOLE_REPORT;
typedef struct {
  dxe_u64 Checks, Status, Error, Stage, EntryCount, Complete, ReturnStatus, ReturnCount, UnmapStatus, UnmapCount, HandleGoneStatus, GopStatus, HiiStatus, TextStatus, PoolStatus, PagesStatus, MapStatus, MapCount, FontCount, FrameHash;
  N976N_CONSOLE_MODULE Module;
} N976N_DEMO_REPORT;
typedef struct {
  dxe_u64 Checks, Status, Error, Stage, WindowBase, WindowSize, UsableBase, UsableSize, PolicyChecks, PolicyStatus, RegisterStatus, AllocateStatus, FreeStatus, MapBeforeType, MapDuringType, MapAfterType, WordsTested, PassCount, GuardChecks, MismatchAddress, Expected, Observed, MapCountBefore, MapCountDuring, MapCountAfter, DescriptorReserve, Complete;
  dxe_u64 MapRecords, MapRecordCount, MapRecordSize, RemainingFreeDescriptors, Reserved;
} N976N_EXT_REPORT;
typedef struct {
  dxe_u64 Buffer, Size, Key, DescriptorSize, Count, Type, Status;
} N976N_EXT_MAP_RECORD;
typedef struct {
  dxe_u64 Checks, Status, Error, Stage, Complete, PageBytes, PageCount, PoolBytes, PageAddress0, PageAddress1, PoolAddress0, PoolAddress1, PoolBase0, PoolBase1, PoolSpan0, PoolSpan1, PageAllocStatus0, PageAllocStatus1, PageFreeStatus0, PageFreeStatus1, PoolAllocStatus0, PoolAllocStatus1, PoolFreeStatus0, PoolFreeStatus1, LiveChecks, PatternChecks, BytesVerified, GuardChecks, MapChecks, FinalConventionalBytes, MapRecords, MapRecordCount, MapRecordSize, DescriptorReserve, RemainingFreeDescriptors, MismatchAddress, Expected, Observed, PoolMetadataChecks, AllocationCount, FreeCount, PageReuse, PoolReuse, FinalMapCount, Sctlr, Cpacr, Sp, Tpl;
  dxe_u64 Reserved[16];
} N976N_GENERIC_REPORT;
typedef struct {
  dxe_u64 Buffer, Size, Key, DescriptorSize, Count, Status;
  dxe_u64 PageAddress, PageBytes, PoolAddress, PoolBytes, PoolBase, PoolSpan;
  dxe_u64 LiveMask, ConventionalBytes, DescriptorReserve;
} N976N_GENERIC_MAP_RECORD;
typedef struct {
  dxe_u64 Checks, Status, Error, Stage, Complete, SetupChecks, CounterFrequency, CounterBefore, CounterAfter, CounterDelta, CounterReadCount, StallStatus, StallRequestUs, StallTicks, StallCount, StallRecords, StallRecordCount, StallRecordSize, CrcStatus, CrcKnown, CrcChecks, BsCrc, StCrc, RtCrc, DsCrc, DebugCrc, MetronomeProtocol, MetronomeInstallStatus, CrcFunction, MetronomeWait, TplBefore, TplAfter, DaifBefore, DaifAfter, TransitionEvent, TransitionCount, TransitionTpl, TransitionSignalStatus, TransitionCloseStatus, EntryCount, ReturnStatus, ReturnCount, UnmapStatus, UnmapCount, HandleGoneStatus, PageAllocStatus, PageFreeStatus, PageAddress, PageBytes, PoolAllocStatus, PoolFreeStatus, PoolAddress, PoolBytes, PoolBase, PoolSpan, EventCreateStatus, EventSignalStatus, EventCloseStatus, EventCount, EventTpl, WaitEvent, WaitCreateStatus, WaitSignalStatus, WaitStatus, WaitIndex, WaitCloseStatus, TextStatus, BytesVerified, MapRecords, MapRecordCount, MapRecordSize, MapChecks, AuxPagesMax, AuxPagesFinal, DescriptorReserve, RemainingFreeDescriptors, GuardChecks, Cpacr, Sctlr, Sp, MismatchAddress, Expected, Observed, FinalTpl, AppPhase, PendingChecks, FinalMapCount, CpuGuardChecks;
  dxe_u64 Reserved[28];
  N976N_CONSOLE_MODULE Module;
} N976N_LIVE_REPORT;
typedef struct {
  dxe_u64 Magic, Version, Size, Mode, BootInfoAddress, ReportAddress, ControlCallback, Reserved;
} N976N_LIVE_OPTIONS;
typedef struct {
  dxe_u64 Kind, RequestUs, Start, End, Ticks, MinimumTicks, Status, Phase;
} N976N_LIVE_STALL_RECORD;
typedef struct {
  dxe_u64 Buffer, Size, Key, DescriptorSize, Count, Status, Phase;
  dxe_u64 PageAddress, PageBytes, PoolAddress, PoolBase, PoolSpan;
  dxe_u64 AuxBytes, ConventionalBytes, DescriptorReserve;
} N976N_LIVE_MAP_RECORD;

typedef struct {
  dxe_u64 Checks, Status, Error, Stage, Complete, ActiveModule, DiskBase, DiskSize, DiskCrcBefore, DiskCrcAfter, VolumeHandle, BlockIo, DiskIo, FileSystem, DevicePath, FilePath, InstallStatus, ConnectStatus, OpenVolumeStatus, OpenFileStatus, ReadStatus, ReadBytes, ReadCompare, FileCloseStatus, RootCloseStatus, ReadOnlyStatus, BlockReadCount, DiskReadCount, ReadBytesTotal, WriteAttempts, RejectedReads, EntryCount, ReturnStatus, ReturnCount, UnmapStatus, UnmapCount, HandleGoneStatus, TextStatus, RelocValue, RelocPointer, DataValue, BssValue, AppChecks, AppStatus, AppComplete, MapRecords, MapRecordCount, MapRecordSize, MapChecks, GuardChecks, CrcChecks, DescriptorReserve, RemainingFreeDescriptors, FinalTpl, DebugCount, LoadedDeviceHandle, LoadedFilePath, PayloadLoadSource, PayloadLoadSize, CodeBytes, AuxBytes, FinalConventionalBytes, PathCheck, ModuleChecks, DriverBinding, DriverBindingCount, DiskStatus, CpuChecks, Sctlr, Cpacr, Sp, BlockNegativeChecks, DiskNegativeChecks, FileInfoSize, FileSize, MissingStatus, PendingChecks, ReadBuffer, ReadBufferSize, DiskUnchanged;
  N976N_CONSOLE_MODULE Module[3]; /* English, FAT, file-backed application. */
  dxe_u64 Reserved[12];
} N976N_VOLUME_REPORT;
typedef struct {
  dxe_u64 Magic, Size, BootInfoAddress, ReportAddress, VolumeHandle, DevicePath, Reserved0, Reserved1;
} N976N_VOLUME_OPTIONS;
typedef struct {
  dxe_u64 Buffer, Size, Key, DescriptorSize, Count, Status, Phase, CodeBytes, AuxBytes, ConventionalBytes, DescriptorReserve, Reserved;
} N976N_VOLUME_MAP_RECORD;

typedef struct { dxe_u64 Base, Size; } N976N_IMAGE_RANGE;
typedef struct {
  dxe_u64 Magic, Size, Owner, BackingBase, BackingSize, ImageBase, ImageSize;
  dxe_u64 Entry, RangeCount, Status, Reserved0, Reserved1;
  N976N_IMAGE_RANGE Ranges[N976N_IMAGE_MAX_RANGES];
} N976N_IMAGE_MAP_REQUEST;
/* Raw registry records are independent of the DXE registry. State 0=free,
 * 1=mapped; released records retain their last ranges for forensic inspection. */
typedef struct {
  dxe_u64 Owner, BackingBase, BackingSize, ImageBase, ImageSize, Entry, RangeCount, State;
  N976N_IMAGE_RANGE Ranges[N976N_IMAGE_MAX_RANGES];
} N976N_IMAGE_RAW_RECORD;
typedef struct {
  dxe_u64 Checks, Status, Error, Stage, Complete, LoadCount, StartCount, UnloadCount, MapCount, UnmapCount, RejectCount, RollbackCount, ActiveCount, PeakCount, ReturnCount, ExitCount, PrestartUnloadCount, ChainStatus, MapChecks, GuardChecks, CpuChecks, FinalTpl, RegistryAddress, RecordSize, Capacity, SourceReadCount, HookLoadCount, HookUnloadCount, ParentIntactCount, RawRegistryAddress, RawRecordSize, RawCapacity, RawActiveCount, RawMapCount, RawUnmapCount, RawRejectCount, RawFatal, RawChecks, StandardStatus, ExitStatus, UnloadStatus, MalformedStatus, UnsupportedStatus, ExhaustionStatus, FinalConventionalBytes, FinalMapCount, DiskCrcBefore, DiskCrcAfter;
  dxe_u64 Reserved[16];
} N976N_IMAGE_REPORT;
/* FIX1 appended diagnostics preserve the original 224-byte continuation prefix
 * and every offset/size in N976N_BOOT_REPORT and N976N_DXE_REPORT. All values
 * are passive observations. Gate==0 means no diagnostic rejection recorded. */
typedef struct {
  dxe_u64 Gate, Detail, Output, Requested, PmuOverflow, PmuPmcr, CpuSctlr, CpuMask;
  dxe_u64 PmuCountEnable, PmuInterruptEnable, PmuCycleFilter, PmuUserEnable;
} N976N_BOOT_DIAGNOSTIC;
/* SEC29 keeps the 192-byte CPU diagnostic and original 320-byte prefix.
 * Active/Verified fields describe steady WB controls before/after atomics;
 * they do not describe a temporary mapping or restoration. */
typedef struct {
  dxe_u64 Phase, Midr, Mpidr, Isar0, Sctlr, Mair;
  dxe_u64 Scratch, Descriptor, Attempts, StoreStatus, Value, Checks;
  dxe_u64 CachePhase, LeafAddress, ActiveDescriptor, ActiveSctlr, ActiveMair;
  dxe_u64 VerifiedDescriptor, VerifiedSctlr, VerifiedMair, LineBytes, LseOld, LseValue, LseStatus;
} N976N_BOOT_CPU_DIAGNOSTIC;
/* SEC41_FIX5 retains the graphics/cleanup ABI. Four missing-variable results have
 * returned; their stack output pointers are historical and must not be read.
 * The held policy-write request uses the existing Diagnostic input fields.
 * The prior error-path cleanup remains independently guarded. */
typedef struct {
  dxe_u64 Magic, Size, Checks, Stage, Handle, Buffer, Path, Protocol;
  dxe_u64 CloseCalls, CloseStatus, TextOut, TextMode, TextCalls, TextStatus;
  dxe_u64 Columns, Rows, ColumnsOutput, RowsOutput, FrameBufferBase, FrameBufferSize;
  dxe_u64 Width, Height, PitchBytes, PixelFormat, RestoreChecks;
  dxe_u64 QueryReturned, VariableCalls, VariableReturned, VariableMask, VariableKey;
  dxe_u64 VariableStatus, VariableName, VariableGuid, VariableAttributesOutput, VariableSizeOutput;
  dxe_u64 AllocationCalls, AllocationReturned, AllocationPrevious, AllocationAddress, AllocationStatus;
  dxe_u64 FreeCalls, FreeAddress, FreePages, FreeStatus;
  dxe_u64 FreeReturned, ReallocateCalls, ReallocateReturned;
  dxe_u64 ReallocateAddress, ReallocateStatus, ReallocateOutput;
  dxe_u64 GopCloseCalls, GopCloseStatus, GopCloseReturned;
  dxe_u64 FinalFreeCalls, FinalFreeAddress, FinalFreePages, FinalFreeStatus;
  dxe_u64 FinalFreeReturned;
  dxe_u64 EntryReturnSeen, EntryReturnStatus, EntryReturnHandle, EntryReturnPrivate, TeardownHeld;
} N976N_BOOT_GRAPHICS_REPORT;
typedef struct {
  dxe_u64 Magic, Size, Checks, AllocateCalls, FreeCalls, MapCalls, LivePages;
  dxe_u64 OutputCalls, OutputStatus, AcpiPresent, MessageBytes, MemoryState;
  dxe_u16 Message[64];
  N976N_BOOT_DIAGNOSTIC Diagnostic;
  N976N_BOOT_CPU_DIAGNOSTIC CpuDiagnostic;
  dxe_u64 GraphicsState;
} N976N_BOOT_CONTINUATION_REPORT;
/* SEC28 observes native memory services and the original ACPI diagnostic.
 * Complete means this observation completed, never that Windows booted. */
typedef struct {
  dxe_u64 Checks, Status, Error, Stage, Complete, PayloadBase, PayloadSize, PayloadCrc;
  dxe_u64 ImageBase, ImageSize, Entry, Handle, LoadStatus, StartStatus, UnloadStatus;
  dxe_u64 GetVariableCount, ServiceId, CallerPc, OriginalStatus, ActiveCount;
  dxe_u64 MapChecks, GuardChecks, CpuChecks, FinalTpl, SourceCopy, SourceCopySize;
  dxe_u64 LoadCountBefore, UnmapCountBefore, VariableCode, VendorGuidMatch;
  dxe_u64 LoadCountAfter, UnmapCountAfter, Returned;
  dxe_u64 VariableChecks, SetupModeValue, SecureBootValue, HandleProtocolCount;
  dxe_u64 LoadedImageStatus, DevicePathStatus, DevicePathHandle, VariableStatus;
  dxe_u64 OriginChecks, DeviceHandle, FilePath, DevicePath;
  dxe_u64 AllocatePagesCount, AllocationType, AllocationMemoryType;
  dxe_u64 AllocationPages, AllocationAddress, AllocationStatus;
  dxe_u64 GetMemoryMapCount, MemoryMapStatus, MemoryMapBytes;
  dxe_u64 MemoryMapDescriptorSize, MemoryMapDescriptorVersion, ArchitectureChecks;
  dxe_u64 SctlrBefore, SctlrWindows, SctlrAfter, PmcrBefore, PmcrAfter, PmuChecks;
  dxe_u64 Reserved[1];
} N976N_BOOT_REPORT;

typedef void (*N976N_DXE_SCREEN_CALLBACK)(dxe_u64 Event, dxe_u64 Value);
typedef struct {
  dxe_u64 Version, ImageBase, ImageEnd, HeapBase, HeapEnd, FvBase, FvSize;
  dxe_u64 DxeBase, DxeSize, DxeEntry, DxeTextBase, DxeTextEnd;
  dxe_u64 StackBase, StackSize, ReportAddress, ReportSize, ScreenCallback;
  dxe_u64 HiiPeBase, HiiPeSize, GraphicsPeBase, GraphicsPeSize;
  dxe_u64 DemoPeBase, DemoPeSize;
  dxe_u64 ExternalBase, ExternalSize, ExternalPolicyChecks, ExternalPolicyStatus;
} N976N_DXE_BOOT_INFO;
typedef struct {
  dxe_u64 Magic, Size, Checks, Status, Stage, Error;
  dxe_u64 SystemTable, BootServices, DxeImage, HobList, HeapBase, HeapEnd;
  dxe_u64 PageAddress, PageStatus, PageFreeStatus;
  dxe_u64 PoolAddress, PoolStatus, PoolFreeStatus;
  dxe_u64 MapStatus, MapSize, MapCount, MapKey;
  dxe_u64 ProtocolInstallStatus, ProtocolLocateStatus, ProtocolRemoveStatus, ProtocolFound;
  dxe_u64 Sctlr, GuardChecks, AssertLine, Complete, MapBuffer, MapDescriptorSize;
  /* Preserve wrapper FP fields 256..319 and FB evidence 512..1023. */
  dxe_u64 FpCpacrBefore, FpCpacrAfter, FpChecks, FpStatus, FpObserved0, FpObserved1, FpExpected0, FpExpected1, DriverChecks, DriverStatus, DispatchNoArchCount, DriverEntryCount, DriverReturned, DriverImage, DriverImageSize, DriverEntry, DriverTextBase, DriverTextEnd, DriverHandle, DispatchBeginCount, DriverEventCount, DriverEventCreateStatus, DriverEventSignalStatus, DriverEventCloseStatus, DriverProtocolStatus, DriverProtocolAddress, DriverLoadedImageStatus, DriverMapStatus, DriverMapCount, DriverReturnStatus, DriverComplete, DebugTable;
  N976N_FB_REPORT Fb;
  N976N_GOP_REPORT Gop;
  N976N_CONSOLE_REPORT Console;
  N976N_DEMO_REPORT Demo;
  N976N_EXT_REPORT External;
  N976N_GENERIC_REPORT Generic;
  N976N_LIVE_REPORT Live;
  N976N_VOLUME_REPORT Volume;
  N976N_IMAGE_REPORT Chain;
  N976N_BOOT_REPORT Boot;
} N976N_DXE_REPORT;
typedef struct {
  dxe_u64 Magic, Size, ImageBase, ImageSize, TextBase, TextEnd, Entry, Status;
} N976N_DXE_MAP_REQUEST;
#endif
#endif
