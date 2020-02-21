// Copyright 2016-2019 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package types

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net"

	cniTypes "github.com/containernetworking/cni/pkg/types"
	"github.com/containernetworking/cni/pkg/types/current"
	"github.com/containernetworking/cni/pkg/version"
)

// ENISpec is the ENI specification of a node.
//
// NOTE: This type was duplicated from pkg/k8s/apis/cilium.io/v2 to reduce
// package dependencies. Any changes made here should be reflected in the
// ENISpec type in pkg/k8s/apis/cilium.io/v2 as well.
type ENISpec struct {
	// InstanceID is the AWS InstanceId of the node. The InstanceID is used
	// to retrieve AWS metadata for the node.
	InstanceID string `json:"instance-id,omitempty"`

	// InstanceType is the AWS EC2 instance type, e.g. "m5.large"
	InstanceType string `json:"instance-type,omitempty"`

	// MinAllocate is the minimum number of IPs that must be allocated when
	// the node is first bootstrapped. It defines the minimum base socket
	// of addresses that must be available. After reaching this watermark,
	// the PreAllocate and MaxAboveWatermark logic takes over to continue
	// allocating IPs.
	//
	// +optional
	MinAllocate int `json:"min-allocate,omitempty"`

	// PreAllocate defines the number of IP addresses that must be
	// available for allocation in the IPAMspec. It defines the buffer of
	// addresses available immediately without requiring cilium-operator to
	// get involved.
	//
	// +optional
	PreAllocate int `json:"pre-allocate,omitempty"`

	// MaxAboveWatermark is the maximum number of addresses to allocate
	// beyond the addresses needed to reach the PreAllocate watermark.
	// Going above the watermark can help reduce the number of API calls to
	// allocate IPs, e.g. when a new ENI is allocated, as many secondary
	// IPs as possible are allocated. Limiting the amount can help reduce
	// waste of IPs.
	//
	// +optional
	MaxAboveWatermark int `json:"max-above-watermark,omitempty"`

	// FirstInterfaceIndex is the index of the first ENI to use for IP
	// allocation, e.g. if the node has eth0, eth1, eth2 and
	// FirstInterfaceIndex is set to 1, then only eth1 and eth2 will be
	// used for IP allocation, eth0 will be ignored for PodIP allocation.
	//
	// +optional
	FirstInterfaceIndex *int `json:"first-interface-index,omitempty"`

	// SecurityGroups is the list of security groups to attach to any ENI
	// that is created and attached to the instance.
	//
	// +optional
	SecurityGroups []string `json:"security-groups,omitempty"`

	// SecurityGroupTags is the list of tags to use when evaliating what
	// AWS security groups to use for the ENI.
	//
	// +optional
	SecurityGroupTags map[string]string `json:"security-group-tags,omitempty"`

	// SubnetTags is the list of tags to use when evaluating what AWS
	// subnets to use for ENI and IP allocation
	//
	// +optional
	SubnetTags map[string]string `json:"subnet-tags,omitempty"`

	// VpcID is the VPC ID to use when allocating ENIs
	VpcID string `json:"vpc-id,omitempty"`

	// AvailabilityZone is the availability zone to use when allocating
	// ENIs
	AvailabilityZone string `json:"availability-zone,omitempty"`

	// DeleteOnTermination defines that the ENI should be deleted when the
	// associated instance is terminated. If the parameter is not set the
	// default behavior is to delete the ENI on instance termination.
	//
	// +optional
	DeleteOnTermination *bool `json:"delete-on-termination,omitempty"`
}

// NetConf is the Cilium specific CNI network configuration
type NetConf struct {
	cniTypes.NetConf
	MTU         int     `json:"mtu"`
	Args        Args    `json:"args"`
	ENI         ENISpec `json:"eni,omitempty"`
	EnableDebug bool    `json:"enable-debug"`
}

// NetConfList is a CNI chaining configuration
type NetConfList struct {
	Plugins []*NetConf `json:"plugins,omitempty"`
}

func parsePrevResult(n *NetConf) (*NetConf, error) {
	if n.RawPrevResult != nil {
		resultBytes, err := json.Marshal(n.RawPrevResult)
		if err != nil {
			return nil, fmt.Errorf("could not serialize prevResult: %v", err)
		}
		res, err := version.NewResult(n.CNIVersion, resultBytes)
		if err != nil {
			return nil, fmt.Errorf("could not parse prevResult: %v", err)
		}
		n.PrevResult, err = current.NewResultFromResult(res)
		if err != nil {
			return nil, fmt.Errorf("could not convert result to current version: %v", err)
		}
	}

	return n, nil
}

// ReadNetConf reads a CNI configuration file and returns the corresponding
// NetConf structure
func ReadNetConf(path string) (*NetConf, error) {
	b, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("Unable to read CNI configuration '%s': %s", path, err)
	}

	netConfList := &NetConfList{}
	if err := json.Unmarshal(b, netConfList); err == nil {
		for _, plugin := range netConfList.Plugins {
			if plugin.Type == "cilium-cni" {
				return parsePrevResult(plugin)
			}
		}
	}

	return LoadNetConf(b)
}

// LoadNetConf unmarshals a Cilium network configuration from JSON and returns
// a NetConf together with the CNI version
func LoadNetConf(bytes []byte) (*NetConf, error) {
	n := &NetConf{}
	if err := json.Unmarshal(bytes, n); err != nil {
		return nil, fmt.Errorf("failed to load netconf: %s", err)
	}

	return parsePrevResult(n)

}

// ArgsSpec is the specification of additional arguments of the CNI ADD call
type ArgsSpec struct {
	cniTypes.CommonArgs
	IP                         net.IP
	K8S_POD_NAME               cniTypes.UnmarshallableString
	K8S_POD_NAMESPACE          cniTypes.UnmarshallableString
	K8S_POD_INFRA_CONTAINER_ID cniTypes.UnmarshallableString
}

// Args contains arbitrary information a scheduler
// can pass to the cni plugin
type Args struct {
	Mesos Mesos `json:"org.apache.mesos,omitempty"`
}

// Mesos contains network-specific information from the scheduler to the cni plugin
type Mesos struct {
	NetworkInfo NetworkInfo `json:"network_info"`
}

// NetworkInfo supports passing only labels from mesos
type NetworkInfo struct {
	Name   string `json:"name"`
	Labels struct {
		Labels []struct {
			Key   string `json:"key"`
			Value string `json:"value"`
		} `json:"labels,omitempty"`
	} `json:"labels,omitempty"`
}
