// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.31.0
// 	protoc        (unknown)
// source: spacemesh/v1/smesher.proto

package spacemeshv1

import (
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	emptypb "google.golang.org/protobuf/types/known/emptypb"
	reflect "reflect"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

var File_spacemesh_v1_smesher_proto protoreflect.FileDescriptor

var file_spacemesh_v1_smesher_proto_rawDesc = []byte{
	0x0a, 0x1a, 0x73, 0x70, 0x61, 0x63, 0x65, 0x6d, 0x65, 0x73, 0x68, 0x2f, 0x76, 0x31, 0x2f, 0x73,
	0x6d, 0x65, 0x73, 0x68, 0x65, 0x72, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x0c, 0x73, 0x70,
	0x61, 0x63, 0x65, 0x6d, 0x65, 0x73, 0x68, 0x2e, 0x76, 0x31, 0x1a, 0x1b, 0x67, 0x6f, 0x6f, 0x67,
	0x6c, 0x65, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2f, 0x65, 0x6d, 0x70, 0x74,
	0x79, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x20, 0x73, 0x70, 0x61, 0x63, 0x65, 0x6d, 0x65,
	0x73, 0x68, 0x2f, 0x76, 0x31, 0x2f, 0x73, 0x6d, 0x65, 0x73, 0x68, 0x65, 0x72, 0x5f, 0x74, 0x79,
	0x70, 0x65, 0x73, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x32, 0xa1, 0x09, 0x0a, 0x0e, 0x53, 0x6d,
	0x65, 0x73, 0x68, 0x65, 0x72, 0x53, 0x65, 0x72, 0x76, 0x69, 0x63, 0x65, 0x12, 0x46, 0x0a, 0x0a,
	0x49, 0x73, 0x53, 0x6d, 0x65, 0x73, 0x68, 0x69, 0x6e, 0x67, 0x12, 0x16, 0x2e, 0x67, 0x6f, 0x6f,
	0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e, 0x45, 0x6d, 0x70,
	0x74, 0x79, 0x1a, 0x20, 0x2e, 0x73, 0x70, 0x61, 0x63, 0x65, 0x6d, 0x65, 0x73, 0x68, 0x2e, 0x76,
	0x31, 0x2e, 0x49, 0x73, 0x53, 0x6d, 0x65, 0x73, 0x68, 0x69, 0x6e, 0x67, 0x52, 0x65, 0x73, 0x70,
	0x6f, 0x6e, 0x73, 0x65, 0x12, 0x58, 0x0a, 0x0d, 0x53, 0x74, 0x61, 0x72, 0x74, 0x53, 0x6d, 0x65,
	0x73, 0x68, 0x69, 0x6e, 0x67, 0x12, 0x22, 0x2e, 0x73, 0x70, 0x61, 0x63, 0x65, 0x6d, 0x65, 0x73,
	0x68, 0x2e, 0x76, 0x31, 0x2e, 0x53, 0x74, 0x61, 0x72, 0x74, 0x53, 0x6d, 0x65, 0x73, 0x68, 0x69,
	0x6e, 0x67, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x1a, 0x23, 0x2e, 0x73, 0x70, 0x61, 0x63,
	0x65, 0x6d, 0x65, 0x73, 0x68, 0x2e, 0x76, 0x31, 0x2e, 0x53, 0x74, 0x61, 0x72, 0x74, 0x53, 0x6d,
	0x65, 0x73, 0x68, 0x69, 0x6e, 0x67, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x12, 0x55,
	0x0a, 0x0c, 0x53, 0x74, 0x6f, 0x70, 0x53, 0x6d, 0x65, 0x73, 0x68, 0x69, 0x6e, 0x67, 0x12, 0x21,
	0x2e, 0x73, 0x70, 0x61, 0x63, 0x65, 0x6d, 0x65, 0x73, 0x68, 0x2e, 0x76, 0x31, 0x2e, 0x53, 0x74,
	0x6f, 0x70, 0x53, 0x6d, 0x65, 0x73, 0x68, 0x69, 0x6e, 0x67, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73,
	0x74, 0x1a, 0x22, 0x2e, 0x73, 0x70, 0x61, 0x63, 0x65, 0x6d, 0x65, 0x73, 0x68, 0x2e, 0x76, 0x31,
	0x2e, 0x53, 0x74, 0x6f, 0x70, 0x53, 0x6d, 0x65, 0x73, 0x68, 0x69, 0x6e, 0x67, 0x52, 0x65, 0x73,
	0x70, 0x6f, 0x6e, 0x73, 0x65, 0x12, 0x44, 0x0a, 0x09, 0x53, 0x6d, 0x65, 0x73, 0x68, 0x65, 0x72,
	0x49, 0x44, 0x12, 0x16, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74,
	0x6f, 0x62, 0x75, 0x66, 0x2e, 0x45, 0x6d, 0x70, 0x74, 0x79, 0x1a, 0x1f, 0x2e, 0x73, 0x70, 0x61,
	0x63, 0x65, 0x6d, 0x65, 0x73, 0x68, 0x2e, 0x76, 0x31, 0x2e, 0x53, 0x6d, 0x65, 0x73, 0x68, 0x65,
	0x72, 0x49, 0x44, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x12, 0x42, 0x0a, 0x08, 0x43,
	0x6f, 0x69, 0x6e, 0x62, 0x61, 0x73, 0x65, 0x12, 0x16, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65,
	0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e, 0x45, 0x6d, 0x70, 0x74, 0x79, 0x1a,
	0x1e, 0x2e, 0x73, 0x70, 0x61, 0x63, 0x65, 0x6d, 0x65, 0x73, 0x68, 0x2e, 0x76, 0x31, 0x2e, 0x43,
	0x6f, 0x69, 0x6e, 0x62, 0x61, 0x73, 0x65, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x12,
	0x52, 0x0a, 0x0b, 0x53, 0x65, 0x74, 0x43, 0x6f, 0x69, 0x6e, 0x62, 0x61, 0x73, 0x65, 0x12, 0x20,
	0x2e, 0x73, 0x70, 0x61, 0x63, 0x65, 0x6d, 0x65, 0x73, 0x68, 0x2e, 0x76, 0x31, 0x2e, 0x53, 0x65,
	0x74, 0x43, 0x6f, 0x69, 0x6e, 0x62, 0x61, 0x73, 0x65, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74,
	0x1a, 0x21, 0x2e, 0x73, 0x70, 0x61, 0x63, 0x65, 0x6d, 0x65, 0x73, 0x68, 0x2e, 0x76, 0x31, 0x2e,
	0x53, 0x65, 0x74, 0x43, 0x6f, 0x69, 0x6e, 0x62, 0x61, 0x73, 0x65, 0x52, 0x65, 0x73, 0x70, 0x6f,
	0x6e, 0x73, 0x65, 0x12, 0x3e, 0x0a, 0x06, 0x4d, 0x69, 0x6e, 0x47, 0x61, 0x73, 0x12, 0x16, 0x2e,
	0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e,
	0x45, 0x6d, 0x70, 0x74, 0x79, 0x1a, 0x1c, 0x2e, 0x73, 0x70, 0x61, 0x63, 0x65, 0x6d, 0x65, 0x73,
	0x68, 0x2e, 0x76, 0x31, 0x2e, 0x4d, 0x69, 0x6e, 0x47, 0x61, 0x73, 0x52, 0x65, 0x73, 0x70, 0x6f,
	0x6e, 0x73, 0x65, 0x12, 0x4c, 0x0a, 0x09, 0x53, 0x65, 0x74, 0x4d, 0x69, 0x6e, 0x47, 0x61, 0x73,
	0x12, 0x1e, 0x2e, 0x73, 0x70, 0x61, 0x63, 0x65, 0x6d, 0x65, 0x73, 0x68, 0x2e, 0x76, 0x31, 0x2e,
	0x53, 0x65, 0x74, 0x4d, 0x69, 0x6e, 0x47, 0x61, 0x73, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74,
	0x1a, 0x1f, 0x2e, 0x73, 0x70, 0x61, 0x63, 0x65, 0x6d, 0x65, 0x73, 0x68, 0x2e, 0x76, 0x31, 0x2e,
	0x53, 0x65, 0x74, 0x4d, 0x69, 0x6e, 0x47, 0x61, 0x73, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73,
	0x65, 0x12, 0x61, 0x0a, 0x10, 0x45, 0x73, 0x74, 0x69, 0x6d, 0x61, 0x74, 0x65, 0x64, 0x52, 0x65,
	0x77, 0x61, 0x72, 0x64, 0x73, 0x12, 0x25, 0x2e, 0x73, 0x70, 0x61, 0x63, 0x65, 0x6d, 0x65, 0x73,
	0x68, 0x2e, 0x76, 0x31, 0x2e, 0x45, 0x73, 0x74, 0x69, 0x6d, 0x61, 0x74, 0x65, 0x64, 0x52, 0x65,
	0x77, 0x61, 0x72, 0x64, 0x73, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x1a, 0x26, 0x2e, 0x73,
	0x70, 0x61, 0x63, 0x65, 0x6d, 0x65, 0x73, 0x68, 0x2e, 0x76, 0x31, 0x2e, 0x45, 0x73, 0x74, 0x69,
	0x6d, 0x61, 0x74, 0x65, 0x64, 0x52, 0x65, 0x77, 0x61, 0x72, 0x64, 0x73, 0x52, 0x65, 0x73, 0x70,
	0x6f, 0x6e, 0x73, 0x65, 0x12, 0x50, 0x0a, 0x0f, 0x50, 0x6f, 0x73, 0x74, 0x53, 0x65, 0x74, 0x75,
	0x70, 0x53, 0x74, 0x61, 0x74, 0x75, 0x73, 0x12, 0x16, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65,
	0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e, 0x45, 0x6d, 0x70, 0x74, 0x79, 0x1a,
	0x25, 0x2e, 0x73, 0x70, 0x61, 0x63, 0x65, 0x6d, 0x65, 0x73, 0x68, 0x2e, 0x76, 0x31, 0x2e, 0x50,
	0x6f, 0x73, 0x74, 0x53, 0x65, 0x74, 0x75, 0x70, 0x53, 0x74, 0x61, 0x74, 0x75, 0x73, 0x52, 0x65,
	0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x12, 0x5e, 0x0a, 0x15, 0x50, 0x6f, 0x73, 0x74, 0x53, 0x65,
	0x74, 0x75, 0x70, 0x53, 0x74, 0x61, 0x74, 0x75, 0x73, 0x53, 0x74, 0x72, 0x65, 0x61, 0x6d, 0x12,
	0x16, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75,
	0x66, 0x2e, 0x45, 0x6d, 0x70, 0x74, 0x79, 0x1a, 0x2b, 0x2e, 0x73, 0x70, 0x61, 0x63, 0x65, 0x6d,
	0x65, 0x73, 0x68, 0x2e, 0x76, 0x31, 0x2e, 0x50, 0x6f, 0x73, 0x74, 0x53, 0x65, 0x74, 0x75, 0x70,
	0x53, 0x74, 0x61, 0x74, 0x75, 0x73, 0x53, 0x74, 0x72, 0x65, 0x61, 0x6d, 0x52, 0x65, 0x73, 0x70,
	0x6f, 0x6e, 0x73, 0x65, 0x30, 0x01, 0x12, 0x67, 0x0a, 0x12, 0x50, 0x6f, 0x73, 0x74, 0x53, 0x65,
	0x74, 0x75, 0x70, 0x50, 0x72, 0x6f, 0x76, 0x69, 0x64, 0x65, 0x72, 0x73, 0x12, 0x27, 0x2e, 0x73,
	0x70, 0x61, 0x63, 0x65, 0x6d, 0x65, 0x73, 0x68, 0x2e, 0x76, 0x31, 0x2e, 0x50, 0x6f, 0x73, 0x74,
	0x53, 0x65, 0x74, 0x75, 0x70, 0x50, 0x72, 0x6f, 0x76, 0x69, 0x64, 0x65, 0x72, 0x73, 0x52, 0x65,
	0x71, 0x75, 0x65, 0x73, 0x74, 0x1a, 0x28, 0x2e, 0x73, 0x70, 0x61, 0x63, 0x65, 0x6d, 0x65, 0x73,
	0x68, 0x2e, 0x76, 0x31, 0x2e, 0x50, 0x6f, 0x73, 0x74, 0x53, 0x65, 0x74, 0x75, 0x70, 0x50, 0x72,
	0x6f, 0x76, 0x69, 0x64, 0x65, 0x72, 0x73, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x12,
	0x46, 0x0a, 0x0a, 0x50, 0x6f, 0x73, 0x74, 0x43, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x12, 0x16, 0x2e,
	0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e,
	0x45, 0x6d, 0x70, 0x74, 0x79, 0x1a, 0x20, 0x2e, 0x73, 0x70, 0x61, 0x63, 0x65, 0x6d, 0x65, 0x73,
	0x68, 0x2e, 0x76, 0x31, 0x2e, 0x50, 0x6f, 0x73, 0x74, 0x43, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x52,
	0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x12, 0x64, 0x0a, 0x11, 0x55, 0x70, 0x64, 0x61, 0x74,
	0x65, 0x50, 0x6f, 0x65, 0x74, 0x53, 0x65, 0x72, 0x76, 0x65, 0x72, 0x73, 0x12, 0x26, 0x2e, 0x73,
	0x70, 0x61, 0x63, 0x65, 0x6d, 0x65, 0x73, 0x68, 0x2e, 0x76, 0x31, 0x2e, 0x55, 0x70, 0x64, 0x61,
	0x74, 0x65, 0x50, 0x6f, 0x65, 0x74, 0x53, 0x65, 0x72, 0x76, 0x65, 0x72, 0x73, 0x52, 0x65, 0x71,
	0x75, 0x65, 0x73, 0x74, 0x1a, 0x27, 0x2e, 0x73, 0x70, 0x61, 0x63, 0x65, 0x6d, 0x65, 0x73, 0x68,
	0x2e, 0x76, 0x31, 0x2e, 0x55, 0x70, 0x64, 0x61, 0x74, 0x65, 0x50, 0x6f, 0x65, 0x74, 0x53, 0x65,
	0x72, 0x76, 0x65, 0x72, 0x73, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x42, 0xb1, 0x01,
	0x0a, 0x10, 0x63, 0x6f, 0x6d, 0x2e, 0x73, 0x70, 0x61, 0x63, 0x65, 0x6d, 0x65, 0x73, 0x68, 0x2e,
	0x76, 0x31, 0x42, 0x0c, 0x53, 0x6d, 0x65, 0x73, 0x68, 0x65, 0x72, 0x50, 0x72, 0x6f, 0x74, 0x6f,
	0x50, 0x01, 0x5a, 0x3e, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x73,
	0x70, 0x61, 0x63, 0x65, 0x6d, 0x65, 0x73, 0x68, 0x6f, 0x73, 0x2f, 0x61, 0x70, 0x69, 0x2f, 0x72,
	0x65, 0x6c, 0x65, 0x61, 0x73, 0x65, 0x2f, 0x67, 0x6f, 0x2f, 0x73, 0x70, 0x61, 0x63, 0x65, 0x6d,
	0x65, 0x73, 0x68, 0x2f, 0x76, 0x31, 0x3b, 0x73, 0x70, 0x61, 0x63, 0x65, 0x6d, 0x65, 0x73, 0x68,
	0x76, 0x31, 0xa2, 0x02, 0x03, 0x53, 0x58, 0x58, 0xaa, 0x02, 0x0c, 0x53, 0x70, 0x61, 0x63, 0x65,
	0x6d, 0x65, 0x73, 0x68, 0x2e, 0x56, 0x31, 0xca, 0x02, 0x0c, 0x53, 0x70, 0x61, 0x63, 0x65, 0x6d,
	0x65, 0x73, 0x68, 0x5c, 0x56, 0x31, 0xe2, 0x02, 0x18, 0x53, 0x70, 0x61, 0x63, 0x65, 0x6d, 0x65,
	0x73, 0x68, 0x5c, 0x56, 0x31, 0x5c, 0x47, 0x50, 0x42, 0x4d, 0x65, 0x74, 0x61, 0x64, 0x61, 0x74,
	0x61, 0xea, 0x02, 0x0d, 0x53, 0x70, 0x61, 0x63, 0x65, 0x6d, 0x65, 0x73, 0x68, 0x3a, 0x3a, 0x56,
	0x31, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var file_spacemesh_v1_smesher_proto_goTypes = []interface{}{
	(*emptypb.Empty)(nil),                 // 0: google.protobuf.Empty
	(*StartSmeshingRequest)(nil),          // 1: spacemesh.v1.StartSmeshingRequest
	(*StopSmeshingRequest)(nil),           // 2: spacemesh.v1.StopSmeshingRequest
	(*SetCoinbaseRequest)(nil),            // 3: spacemesh.v1.SetCoinbaseRequest
	(*SetMinGasRequest)(nil),              // 4: spacemesh.v1.SetMinGasRequest
	(*EstimatedRewardsRequest)(nil),       // 5: spacemesh.v1.EstimatedRewardsRequest
	(*PostSetupProvidersRequest)(nil),     // 6: spacemesh.v1.PostSetupProvidersRequest
	(*UpdatePoetServersRequest)(nil),      // 7: spacemesh.v1.UpdatePoetServersRequest
	(*IsSmeshingResponse)(nil),            // 8: spacemesh.v1.IsSmeshingResponse
	(*StartSmeshingResponse)(nil),         // 9: spacemesh.v1.StartSmeshingResponse
	(*StopSmeshingResponse)(nil),          // 10: spacemesh.v1.StopSmeshingResponse
	(*SmesherIDResponse)(nil),             // 11: spacemesh.v1.SmesherIDResponse
	(*CoinbaseResponse)(nil),              // 12: spacemesh.v1.CoinbaseResponse
	(*SetCoinbaseResponse)(nil),           // 13: spacemesh.v1.SetCoinbaseResponse
	(*MinGasResponse)(nil),                // 14: spacemesh.v1.MinGasResponse
	(*SetMinGasResponse)(nil),             // 15: spacemesh.v1.SetMinGasResponse
	(*EstimatedRewardsResponse)(nil),      // 16: spacemesh.v1.EstimatedRewardsResponse
	(*PostSetupStatusResponse)(nil),       // 17: spacemesh.v1.PostSetupStatusResponse
	(*PostSetupStatusStreamResponse)(nil), // 18: spacemesh.v1.PostSetupStatusStreamResponse
	(*PostSetupProvidersResponse)(nil),    // 19: spacemesh.v1.PostSetupProvidersResponse
	(*PostConfigResponse)(nil),            // 20: spacemesh.v1.PostConfigResponse
	(*UpdatePoetServersResponse)(nil),     // 21: spacemesh.v1.UpdatePoetServersResponse
}
var file_spacemesh_v1_smesher_proto_depIdxs = []int32{
	0,  // 0: spacemesh.v1.SmesherService.IsSmeshing:input_type -> google.protobuf.Empty
	1,  // 1: spacemesh.v1.SmesherService.StartSmeshing:input_type -> spacemesh.v1.StartSmeshingRequest
	2,  // 2: spacemesh.v1.SmesherService.StopSmeshing:input_type -> spacemesh.v1.StopSmeshingRequest
	0,  // 3: spacemesh.v1.SmesherService.SmesherID:input_type -> google.protobuf.Empty
	0,  // 4: spacemesh.v1.SmesherService.Coinbase:input_type -> google.protobuf.Empty
	3,  // 5: spacemesh.v1.SmesherService.SetCoinbase:input_type -> spacemesh.v1.SetCoinbaseRequest
	0,  // 6: spacemesh.v1.SmesherService.MinGas:input_type -> google.protobuf.Empty
	4,  // 7: spacemesh.v1.SmesherService.SetMinGas:input_type -> spacemesh.v1.SetMinGasRequest
	5,  // 8: spacemesh.v1.SmesherService.EstimatedRewards:input_type -> spacemesh.v1.EstimatedRewardsRequest
	0,  // 9: spacemesh.v1.SmesherService.PostSetupStatus:input_type -> google.protobuf.Empty
	0,  // 10: spacemesh.v1.SmesherService.PostSetupStatusStream:input_type -> google.protobuf.Empty
	6,  // 11: spacemesh.v1.SmesherService.PostSetupProviders:input_type -> spacemesh.v1.PostSetupProvidersRequest
	0,  // 12: spacemesh.v1.SmesherService.PostConfig:input_type -> google.protobuf.Empty
	7,  // 13: spacemesh.v1.SmesherService.UpdatePoetServers:input_type -> spacemesh.v1.UpdatePoetServersRequest
	8,  // 14: spacemesh.v1.SmesherService.IsSmeshing:output_type -> spacemesh.v1.IsSmeshingResponse
	9,  // 15: spacemesh.v1.SmesherService.StartSmeshing:output_type -> spacemesh.v1.StartSmeshingResponse
	10, // 16: spacemesh.v1.SmesherService.StopSmeshing:output_type -> spacemesh.v1.StopSmeshingResponse
	11, // 17: spacemesh.v1.SmesherService.SmesherID:output_type -> spacemesh.v1.SmesherIDResponse
	12, // 18: spacemesh.v1.SmesherService.Coinbase:output_type -> spacemesh.v1.CoinbaseResponse
	13, // 19: spacemesh.v1.SmesherService.SetCoinbase:output_type -> spacemesh.v1.SetCoinbaseResponse
	14, // 20: spacemesh.v1.SmesherService.MinGas:output_type -> spacemesh.v1.MinGasResponse
	15, // 21: spacemesh.v1.SmesherService.SetMinGas:output_type -> spacemesh.v1.SetMinGasResponse
	16, // 22: spacemesh.v1.SmesherService.EstimatedRewards:output_type -> spacemesh.v1.EstimatedRewardsResponse
	17, // 23: spacemesh.v1.SmesherService.PostSetupStatus:output_type -> spacemesh.v1.PostSetupStatusResponse
	18, // 24: spacemesh.v1.SmesherService.PostSetupStatusStream:output_type -> spacemesh.v1.PostSetupStatusStreamResponse
	19, // 25: spacemesh.v1.SmesherService.PostSetupProviders:output_type -> spacemesh.v1.PostSetupProvidersResponse
	20, // 26: spacemesh.v1.SmesherService.PostConfig:output_type -> spacemesh.v1.PostConfigResponse
	21, // 27: spacemesh.v1.SmesherService.UpdatePoetServers:output_type -> spacemesh.v1.UpdatePoetServersResponse
	14, // [14:28] is the sub-list for method output_type
	0,  // [0:14] is the sub-list for method input_type
	0,  // [0:0] is the sub-list for extension type_name
	0,  // [0:0] is the sub-list for extension extendee
	0,  // [0:0] is the sub-list for field type_name
}

func init() { file_spacemesh_v1_smesher_proto_init() }
func file_spacemesh_v1_smesher_proto_init() {
	if File_spacemesh_v1_smesher_proto != nil {
		return
	}
	file_spacemesh_v1_smesher_types_proto_init()
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_spacemesh_v1_smesher_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   0,
			NumExtensions: 0,
			NumServices:   1,
		},
		GoTypes:           file_spacemesh_v1_smesher_proto_goTypes,
		DependencyIndexes: file_spacemesh_v1_smesher_proto_depIdxs,
	}.Build()
	File_spacemesh_v1_smesher_proto = out.File
	file_spacemesh_v1_smesher_proto_rawDesc = nil
	file_spacemesh_v1_smesher_proto_goTypes = nil
	file_spacemesh_v1_smesher_proto_depIdxs = nil
}
