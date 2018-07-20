// Code generated by protoc-gen-go. DO NOT EDIT.
// source: envoy/config/health_checker/redis/v2/redis.proto

/*
Package v2 is a generated protocol buffer package.

It is generated from these files:
	envoy/config/health_checker/redis/v2/redis.proto

It has these top-level messages:
	Redis
*/
package v2

import proto "github.com/golang/protobuf/proto"
import fmt "fmt"
import math "math"

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// This is a compile-time assertion to ensure that this generated file
// is compatible with the proto package it is being compiled against.
// A compilation error at this line likely means your copy of the
// proto package needs to be updated.
const _ = proto.ProtoPackageIsVersion2 // please upgrade the proto package

type Redis struct {
	// If set, optionally perform ``EXISTS <key>`` instead of ``PING``. A return value
	// from Redis of 0 (does not exist) is considered a passing healthcheck. A return value other
	// than 0 is considered a failure. This allows the user to mark a Redis instance for maintenance
	// by setting the specified key to any value and waiting for traffic to drain.
	Key string `protobuf:"bytes,1,opt,name=key" json:"key,omitempty"`
}

func (m *Redis) Reset()                    { *m = Redis{} }
func (m *Redis) String() string            { return proto.CompactTextString(m) }
func (*Redis) ProtoMessage()               {}
func (*Redis) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{0} }

func (m *Redis) GetKey() string {
	if m != nil {
		return m.Key
	}
	return ""
}

func init() {
	proto.RegisterType((*Redis)(nil), "envoy.config.health_checker.redis.v2.Redis")
}

func init() { proto.RegisterFile("envoy/config/health_checker/redis/v2/redis.proto", fileDescriptor0) }

var fileDescriptor0 = []byte{
	// 119 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0xe2, 0x32, 0x48, 0xcd, 0x2b, 0xcb,
	0xaf, 0xd4, 0x4f, 0xce, 0xcf, 0x4b, 0xcb, 0x4c, 0xd7, 0xcf, 0x48, 0x4d, 0xcc, 0x29, 0xc9, 0x88,
	0x4f, 0xce, 0x48, 0x4d, 0xce, 0x4e, 0x2d, 0xd2, 0x2f, 0x4a, 0x4d, 0xc9, 0x2c, 0xd6, 0x2f, 0x33,
	0x82, 0x30, 0xf4, 0x0a, 0x8a, 0xf2, 0x4b, 0xf2, 0x85, 0x54, 0xc0, 0x3a, 0xf4, 0x20, 0x3a, 0xf4,
	0x50, 0x75, 0xe8, 0x41, 0x14, 0x96, 0x19, 0x29, 0x49, 0x72, 0xb1, 0x06, 0x81, 0xd8, 0x42, 0x02,
	0x5c, 0xcc, 0xd9, 0xa9, 0x95, 0x12, 0x8c, 0x0a, 0x8c, 0x1a, 0x9c, 0x41, 0x20, 0xa6, 0x13, 0x4b,
	0x14, 0x53, 0x99, 0x51, 0x12, 0x1b, 0xd8, 0x34, 0x63, 0x40, 0x00, 0x00, 0x00, 0xff, 0xff, 0x9c,
	0xd7, 0xa7, 0xcc, 0x81, 0x00, 0x00, 0x00,
}
