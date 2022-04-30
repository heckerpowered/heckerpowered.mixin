#include "filter.hpp"
namespace filter {
	// const FLT_OPERATION_REGISTRATION operation_registration[]{ { IRP_MJ_CREATE, 0,
	// 	[](PFLT_CALLBACK_DATA data, PCFLT_RELATED_OBJECTS related_objects, PVOID* completion_context) {
	// 	return _FLT_PREOP_CALLBACK_STATUS::FLT_PREOP_SUCCESS_WITH_CALLBACK;
	// 	},
	// 	[](PFLT_CALLBACK_DATA data,PCFLT_RELATED_OBJECTS related_objects,PVOID completion_context,FLT_POST_OPERATION_FLAGS flags) {
	// 	return FLT_POSTOP_CALLBACK_STATUS::FLT_POSTOP_FINISHED_PROCESSING;
	// 	}},
	// 	{ IRP_MJ_OPERATION_END }};
	// 
	// FLT_REGISTRATION filter_registration{
	// 	sizeof(FLT_REGISTRATION),
	// 	FLT_REGISTRATION_VERSION,
	// 	0,
	// 	nullptr,
	// 	operation_registration,
	// };
}