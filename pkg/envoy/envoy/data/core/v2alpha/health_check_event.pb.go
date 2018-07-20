// Code generated by protoc-gen-go. DO NOT EDIT.
// source: envoy/data/core/v2alpha/health_check_event.proto

/*
Package envoy_data_core_v2alpha is a generated protocol buffer package.

It is generated from these files:
	envoy/data/core/v2alpha/health_check_event.proto

It has these top-level messages:
	HealthCheckEvent
	HealthCheckEjectUnhealthy
	HealthCheckAddHealthy
*/
package envoy_data_core_v2alpha

import proto "github.com/golang/protobuf/proto"
import fmt "fmt"
import math "math"
import envoy_api_v2_core1 "github.com/cilium/cilium/pkg/envoy/envoy/api/v2/core"
import _ "github.com/cilium/cilium/pkg/envoy/envoy/api/v2/core"
import _ "github.com/golang/protobuf/ptypes/duration"
import _ "github.com/golang/protobuf/ptypes/wrappers"
import _ "github.com/lyft/protoc-gen-validate/validate"
import _ "github.com/gogo/protobuf/gogoproto"

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// This is a compile-time assertion to ensure that this generated file
// is compatible with the proto package it is being compiled against.
// A compilation error at this line likely means your copy of the
// proto package needs to be updated.
const _ = proto.ProtoPackageIsVersion2 // please upgrade the proto package

type HealthCheckFailureType int32

const (
	HealthCheckFailureType_ACTIVE  HealthCheckFailureType = 0
	HealthCheckFailureType_PASSIVE HealthCheckFailureType = 1
	HealthCheckFailureType_NETWORK HealthCheckFailureType = 2
)

var HealthCheckFailureType_name = map[int32]string{
	0: "ACTIVE",
	1: "PASSIVE",
	2: "NETWORK",
}
var HealthCheckFailureType_value = map[string]int32{
	"ACTIVE":  0,
	"PASSIVE": 1,
	"NETWORK": 2,
}

func (x HealthCheckFailureType) String() string {
	return proto.EnumName(HealthCheckFailureType_name, int32(x))
}
func (HealthCheckFailureType) EnumDescriptor() ([]byte, []int) { return fileDescriptor0, []int{0} }

type HealthCheckerType int32

const (
	HealthCheckerType_HTTP  HealthCheckerType = 0
	HealthCheckerType_TCP   HealthCheckerType = 1
	HealthCheckerType_GRPC  HealthCheckerType = 2
	HealthCheckerType_REDIS HealthCheckerType = 3
)

var HealthCheckerType_name = map[int32]string{
	0: "HTTP",
	1: "TCP",
	2: "GRPC",
	3: "REDIS",
}
var HealthCheckerType_value = map[string]int32{
	"HTTP":  0,
	"TCP":   1,
	"GRPC":  2,
	"REDIS": 3,
}

func (x HealthCheckerType) String() string {
	return proto.EnumName(HealthCheckerType_name, int32(x))
}
func (HealthCheckerType) EnumDescriptor() ([]byte, []int) { return fileDescriptor0, []int{1} }

type HealthCheckEvent struct {
	HealthCheckerType HealthCheckerType           `protobuf:"varint,1,opt,name=health_checker_type,json=healthCheckerType,enum=envoy.data.core.v2alpha.HealthCheckerType" json:"health_checker_type,omitempty"`
	Host              *envoy_api_v2_core1.Address `protobuf:"bytes,2,opt,name=host" json:"host,omitempty"`
	ClusterName       string                      `protobuf:"bytes,3,opt,name=cluster_name,json=clusterName" json:"cluster_name,omitempty"`
	// Types that are valid to be assigned to Event:
	//	*HealthCheckEvent_EjectUnhealthyEvent
	//	*HealthCheckEvent_AddHealthyEvent
	Event isHealthCheckEvent_Event `protobuf_oneof:"event"`
}

func (m *HealthCheckEvent) Reset()                    { *m = HealthCheckEvent{} }
func (m *HealthCheckEvent) String() string            { return proto.CompactTextString(m) }
func (*HealthCheckEvent) ProtoMessage()               {}
func (*HealthCheckEvent) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{0} }

type isHealthCheckEvent_Event interface {
	isHealthCheckEvent_Event()
}

type HealthCheckEvent_EjectUnhealthyEvent struct {
	EjectUnhealthyEvent *HealthCheckEjectUnhealthy `protobuf:"bytes,4,opt,name=eject_unhealthy_event,json=ejectUnhealthyEvent,oneof"`
}
type HealthCheckEvent_AddHealthyEvent struct {
	AddHealthyEvent *HealthCheckAddHealthy `protobuf:"bytes,5,opt,name=add_healthy_event,json=addHealthyEvent,oneof"`
}

func (*HealthCheckEvent_EjectUnhealthyEvent) isHealthCheckEvent_Event() {}
func (*HealthCheckEvent_AddHealthyEvent) isHealthCheckEvent_Event()     {}

func (m *HealthCheckEvent) GetEvent() isHealthCheckEvent_Event {
	if m != nil {
		return m.Event
	}
	return nil
}

func (m *HealthCheckEvent) GetHealthCheckerType() HealthCheckerType {
	if m != nil {
		return m.HealthCheckerType
	}
	return HealthCheckerType_HTTP
}

func (m *HealthCheckEvent) GetHost() *envoy_api_v2_core1.Address {
	if m != nil {
		return m.Host
	}
	return nil
}

func (m *HealthCheckEvent) GetClusterName() string {
	if m != nil {
		return m.ClusterName
	}
	return ""
}

func (m *HealthCheckEvent) GetEjectUnhealthyEvent() *HealthCheckEjectUnhealthy {
	if x, ok := m.GetEvent().(*HealthCheckEvent_EjectUnhealthyEvent); ok {
		return x.EjectUnhealthyEvent
	}
	return nil
}

func (m *HealthCheckEvent) GetAddHealthyEvent() *HealthCheckAddHealthy {
	if x, ok := m.GetEvent().(*HealthCheckEvent_AddHealthyEvent); ok {
		return x.AddHealthyEvent
	}
	return nil
}

// XXX_OneofFuncs is for the internal use of the proto package.
func (*HealthCheckEvent) XXX_OneofFuncs() (func(msg proto.Message, b *proto.Buffer) error, func(msg proto.Message, tag, wire int, b *proto.Buffer) (bool, error), func(msg proto.Message) (n int), []interface{}) {
	return _HealthCheckEvent_OneofMarshaler, _HealthCheckEvent_OneofUnmarshaler, _HealthCheckEvent_OneofSizer, []interface{}{
		(*HealthCheckEvent_EjectUnhealthyEvent)(nil),
		(*HealthCheckEvent_AddHealthyEvent)(nil),
	}
}

func _HealthCheckEvent_OneofMarshaler(msg proto.Message, b *proto.Buffer) error {
	m := msg.(*HealthCheckEvent)
	// event
	switch x := m.Event.(type) {
	case *HealthCheckEvent_EjectUnhealthyEvent:
		b.EncodeVarint(4<<3 | proto.WireBytes)
		if err := b.EncodeMessage(x.EjectUnhealthyEvent); err != nil {
			return err
		}
	case *HealthCheckEvent_AddHealthyEvent:
		b.EncodeVarint(5<<3 | proto.WireBytes)
		if err := b.EncodeMessage(x.AddHealthyEvent); err != nil {
			return err
		}
	case nil:
	default:
		return fmt.Errorf("HealthCheckEvent.Event has unexpected type %T", x)
	}
	return nil
}

func _HealthCheckEvent_OneofUnmarshaler(msg proto.Message, tag, wire int, b *proto.Buffer) (bool, error) {
	m := msg.(*HealthCheckEvent)
	switch tag {
	case 4: // event.eject_unhealthy_event
		if wire != proto.WireBytes {
			return true, proto.ErrInternalBadWireType
		}
		msg := new(HealthCheckEjectUnhealthy)
		err := b.DecodeMessage(msg)
		m.Event = &HealthCheckEvent_EjectUnhealthyEvent{msg}
		return true, err
	case 5: // event.add_healthy_event
		if wire != proto.WireBytes {
			return true, proto.ErrInternalBadWireType
		}
		msg := new(HealthCheckAddHealthy)
		err := b.DecodeMessage(msg)
		m.Event = &HealthCheckEvent_AddHealthyEvent{msg}
		return true, err
	default:
		return false, nil
	}
}

func _HealthCheckEvent_OneofSizer(msg proto.Message) (n int) {
	m := msg.(*HealthCheckEvent)
	// event
	switch x := m.Event.(type) {
	case *HealthCheckEvent_EjectUnhealthyEvent:
		s := proto.Size(x.EjectUnhealthyEvent)
		n += proto.SizeVarint(4<<3 | proto.WireBytes)
		n += proto.SizeVarint(uint64(s))
		n += s
	case *HealthCheckEvent_AddHealthyEvent:
		s := proto.Size(x.AddHealthyEvent)
		n += proto.SizeVarint(5<<3 | proto.WireBytes)
		n += proto.SizeVarint(uint64(s))
		n += s
	case nil:
	default:
		panic(fmt.Sprintf("proto: unexpected type %T in oneof", x))
	}
	return n
}

type HealthCheckEjectUnhealthy struct {
	// The type of failure that caused this ejection.
	FailureType HealthCheckFailureType `protobuf:"varint,1,opt,name=failure_type,json=failureType,enum=envoy.data.core.v2alpha.HealthCheckFailureType" json:"failure_type,omitempty"`
}

func (m *HealthCheckEjectUnhealthy) Reset()                    { *m = HealthCheckEjectUnhealthy{} }
func (m *HealthCheckEjectUnhealthy) String() string            { return proto.CompactTextString(m) }
func (*HealthCheckEjectUnhealthy) ProtoMessage()               {}
func (*HealthCheckEjectUnhealthy) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{1} }

func (m *HealthCheckEjectUnhealthy) GetFailureType() HealthCheckFailureType {
	if m != nil {
		return m.FailureType
	}
	return HealthCheckFailureType_ACTIVE
}

type HealthCheckAddHealthy struct {
	// Whether this addition is the result of the first ever health check on a host, in which case
	// the configured :ref:`healthy threshold <envoy_api_field_core.HealthCheck.healthy_threshold>`
	// is bypassed and the host is immediately added.
	FirstCheck bool `protobuf:"varint,1,opt,name=first_check,json=firstCheck" json:"first_check,omitempty"`
}

func (m *HealthCheckAddHealthy) Reset()                    { *m = HealthCheckAddHealthy{} }
func (m *HealthCheckAddHealthy) String() string            { return proto.CompactTextString(m) }
func (*HealthCheckAddHealthy) ProtoMessage()               {}
func (*HealthCheckAddHealthy) Descriptor() ([]byte, []int) { return fileDescriptor0, []int{2} }

func (m *HealthCheckAddHealthy) GetFirstCheck() bool {
	if m != nil {
		return m.FirstCheck
	}
	return false
}

func init() {
	proto.RegisterType((*HealthCheckEvent)(nil), "envoy.data.core.v2alpha.HealthCheckEvent")
	proto.RegisterType((*HealthCheckEjectUnhealthy)(nil), "envoy.data.core.v2alpha.HealthCheckEjectUnhealthy")
	proto.RegisterType((*HealthCheckAddHealthy)(nil), "envoy.data.core.v2alpha.HealthCheckAddHealthy")
	proto.RegisterEnum("envoy.data.core.v2alpha.HealthCheckFailureType", HealthCheckFailureType_name, HealthCheckFailureType_value)
	proto.RegisterEnum("envoy.data.core.v2alpha.HealthCheckerType", HealthCheckerType_name, HealthCheckerType_value)
}

func init() { proto.RegisterFile("envoy/data/core/v2alpha/health_check_event.proto", fileDescriptor0) }

var fileDescriptor0 = []byte{
	// 525 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x8c, 0x52, 0x41, 0x6f, 0x12, 0x41,
	0x14, 0xee, 0xb0, 0xd0, 0x96, 0x47, 0x53, 0x97, 0xa9, 0xb5, 0x48, 0x4c, 0x4b, 0x38, 0x11, 0x62,
	0x76, 0xcd, 0x7a, 0x31, 0x31, 0x31, 0x01, 0x44, 0x69, 0x4c, 0x2a, 0x59, 0x56, 0xbd, 0x18, 0x37,
	0x03, 0xfb, 0x60, 0x57, 0xb7, 0xec, 0x66, 0x76, 0x58, 0x43, 0xbc, 0xf9, 0x6b, 0x3c, 0x7a, 0x34,
	0x9e, 0xfa, 0x5b, 0xbc, 0xf5, 0x5f, 0x98, 0x9d, 0x81, 0x4a, 0xa5, 0x24, 0xdc, 0xe6, 0xbd, 0x6f,
	0xbe, 0xef, 0x9b, 0x6f, 0xde, 0x83, 0x27, 0x38, 0x4d, 0xa3, 0xb9, 0xe9, 0x31, 0xc1, 0xcc, 0x51,
	0xc4, 0xd1, 0x4c, 0x2d, 0x16, 0xc6, 0x3e, 0x33, 0x7d, 0x64, 0xa1, 0xf0, 0xdd, 0x91, 0x8f, 0xa3,
	0x2f, 0x2e, 0xa6, 0x38, 0x15, 0x46, 0xcc, 0x23, 0x11, 0xd1, 0x13, 0xc9, 0x30, 0x32, 0x86, 0x91,
	0x31, 0x8c, 0x05, 0xa3, 0x7a, 0xa6, 0xa4, 0x58, 0x1c, 0x98, 0xa9, 0xa5, 0xc4, 0x98, 0xe7, 0x71,
	0x4c, 0x12, 0xc5, 0xac, 0x3e, 0x5a, 0xbf, 0x30, 0x64, 0x09, 0x2e, 0xd0, 0xd3, 0x49, 0x14, 0x4d,
	0x42, 0x34, 0x65, 0x35, 0x9c, 0x8d, 0x4d, 0x6f, 0xc6, 0x99, 0x08, 0xa2, 0xe9, 0x26, 0xfc, 0x2b,
	0x67, 0x71, 0x8c, 0x7c, 0xa9, 0x7e, 0x92, 0xb2, 0x30, 0xf0, 0x98, 0x40, 0x73, 0x79, 0x58, 0x00,
	0xf7, 0x27, 0xd1, 0x24, 0x92, 0x47, 0x33, 0x3b, 0xa9, 0x6e, 0xfd, 0xa7, 0x06, 0x7a, 0x4f, 0x66,
	0xec, 0x64, 0x11, 0xbb, 0x59, 0x42, 0x3a, 0x86, 0xa3, 0xd5, 0xdc, 0xc8, 0x5d, 0x31, 0x8f, 0xb1,
	0x42, 0x6a, 0xa4, 0x71, 0x68, 0x35, 0x8d, 0x0d, 0xc9, 0x8d, 0x15, 0x1d, 0xe4, 0xce, 0x3c, 0xc6,
	0x36, 0xfc, 0xbe, 0xbe, 0xd2, 0x0a, 0xdf, 0x49, 0x4e, 0x27, 0x76, 0xd9, 0xff, 0x1f, 0xa6, 0x06,
	0xe4, 0xfd, 0x28, 0x11, 0x95, 0x5c, 0x8d, 0x34, 0x4a, 0x56, 0x75, 0x21, 0xcc, 0xe2, 0xc0, 0x48,
	0x2d, 0x25, 0xdd, 0x52, 0x3f, 0x67, 0xcb, 0x7b, 0xf4, 0x31, 0x1c, 0x8c, 0xc2, 0x59, 0x22, 0x90,
	0xbb, 0x53, 0x76, 0x89, 0x15, 0xad, 0x46, 0x1a, 0xc5, 0x76, 0x31, 0x33, 0xc9, 0xf3, 0x5c, 0x8d,
	0xd8, 0xa5, 0x05, 0x7c, 0xc1, 0x2e, 0x91, 0xfa, 0x70, 0x8c, 0x9f, 0x71, 0x24, 0xdc, 0xd9, 0x54,
	0x59, 0xcf, 0xd5, 0x00, 0x2b, 0x79, 0x69, 0x67, 0x6d, 0x93, 0xa3, 0x9b, 0x09, 0xbc, 0x5b, 0xf2,
	0x7b, 0x3b, 0xf6, 0x11, 0xde, 0xea, 0xa8, 0xff, 0xfa, 0x08, 0x65, 0xe6, 0x79, 0xee, 0x6d, 0x97,
	0x82, 0x74, 0x31, 0xb6, 0x71, 0x69, 0x79, 0x5e, 0xef, 0xc6, 0xe1, 0x1e, 0xbb, 0xa9, 0xa4, 0x7a,
	0xfb, 0x10, 0x0a, 0x52, 0x91, 0x16, 0x7e, 0x5d, 0x5f, 0x69, 0xa4, 0xfe, 0x0d, 0x1e, 0x6e, 0x7c,
	0x21, 0xfd, 0x04, 0x07, 0x63, 0x16, 0x84, 0x33, 0x8e, 0xab, 0x33, 0x33, 0xb7, 0x79, 0xc5, 0x2b,
	0xc5, 0x5b, 0x1b, 0x5c, 0x69, 0xfc, 0x0f, 0xa8, 0x3f, 0x83, 0xe3, 0x3b, 0x1f, 0x4e, 0xcf, 0xa0,
	0x34, 0x0e, 0x78, 0x22, 0xd4, 0xca, 0x48, 0xdf, 0x7d, 0x1b, 0x64, 0x4b, 0x5e, 0x6d, 0xbe, 0x80,
	0x07, 0x77, 0x9b, 0x51, 0x80, 0xdd, 0x56, 0xc7, 0x39, 0x7f, 0xdf, 0xd5, 0x77, 0x68, 0x09, 0xf6,
	0xfa, 0xad, 0xc1, 0x20, 0x2b, 0x48, 0x56, 0x5c, 0x74, 0x9d, 0x0f, 0x6f, 0xed, 0x37, 0x7a, 0xae,
	0xf9, 0x1c, 0xca, 0x6b, 0x0b, 0x46, 0xf7, 0x21, 0xdf, 0x73, 0x9c, 0xbe, 0xbe, 0x43, 0xf7, 0x40,
	0x73, 0x3a, 0x7d, 0x9d, 0x64, 0xad, 0xd7, 0x76, 0xbf, 0xa3, 0xe7, 0x68, 0x11, 0x0a, 0x76, 0xf7,
	0xe5, 0xf9, 0x40, 0xd7, 0xda, 0xf9, 0x1f, 0x7f, 0x4e, 0xc9, 0x70, 0x57, 0xee, 0xfc, 0xd3, 0xbf,
	0x01, 0x00, 0x00, 0xff, 0xff, 0x01, 0xac, 0x99, 0x8e, 0xee, 0x03, 0x00, 0x00,
}
