# Ingress node firewall

[https://github.com/openshift/ingress-node-firewall](https://github.com/openshift/ingress-node-firewall) is an ebpf based
firewall implemented for openshift and kubernetes environments. I have tried testing my ebpf-user-sdk with this firewall and
show the execution below.

# How does the code look
At first look the code of the firewall seems to use a map to store firewall rules
with a key of the form,

```
struct lpm_ip_key_st {
    __u32 prefixLen;
    __u32 ingress_ifindex;
    __u8 ip_data[16];
} __attribute__((packed));
```

and value of the form 


```
struct rulesVal_st {
    struct ruleType_st rules[MAX_RULES_PER_TARGET];
} __attribute__((packed));
```

which is an array of rules,

```
struct ruleType_st {
    __u32 ruleId;
    __u8 protocol;
    __u16 dstPortStart;
    __u16 dstPortEnd;
    __u8 icmpType;
    __u8 icmpCode;
    __u8 action;
} __attribute__((packed));
```

The final map looks like, 
```
/*
 * ingress_node_firewall_table_map: is LPM trie map type
 * key is the ingress interface index and the sourceCIDR.
 * lookup returns an array of rules with actions for the XDP program
 * to process.
 * Note: this map is pinned to specific path in bpffs.
 */
struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __type(key, struct lpm_ip_key_st);
    __type(value, struct rulesVal_st);
    __uint(max_entries, MAX_TARGETS);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} ingress_node_firewall_table_map SEC(".maps");
```

There are two other maps, 

```
/*
 * ingress_node_firewall_events_map: is perf event array map type
 * key is the rule id, packet header is captured and used to generate events.
 */
struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __type(key, __u32);
    __type(value, __u32);
    __uint(max_entries, MAX_CPUS);
} ingress_node_firewall_events_map SEC(".maps");

/*
 * ingress_node_firewall_statistics_map: is per cpu array map type
 * key is the rule id
 * user space collects statistics per CPU and aggregate them.
 */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32); // ruleId
    __type(value, struct ruleStatistics_st);
    __uint(max_entries, MAX_TARGETS);
} ingress_node_firewall_statistics_map SEC(".maps");
```

but they seem to be putting something as output in an event array or per cpu statistics which we can ignore for this example.

# Goal

Our goal here would be to show that we can program the firewall table map using ebpf-client-sdk and 
hence we will focus on the firewall table map.

## Extracting the btf info.

After compiling the firewall and getting an ebpf elf binary we can run the [bpfmap-info-extractor.py](./bpfmap-info-extractor.py)
to get the map information from the elf and a "flatten" version of the type which we can show to the user to program.

```
$ python3 bpfmap-info-extractor.py --elf ./ingress_node_firewall_kernel.o --parsed infw_parsed.btf.json
2023-02-13:14:26:18,696 INFO [bpfmap-info-extractor.py:106] Supplied bpf object, extracting raw btf
2023-02-13:14:26:18,696 INFO [bpfmap-info-extractor.py:96] Executing cmd: bpftool btf dump file ./ingress_node_firewall_kernel.o -p > /tmp/bpf-client-sdk-raw-btf-dump.json
2023-02-13:14:26:18,699 INFO [bpfmap-info-extractor.py:163] output file - infw_parsed.btf.json
2023-02-13:14:26:18,700 INFO [bpfmap-info-extractor.py:166] parsed btf is dumped to infw_parsed.btf.json which is to be used as input to cli
```

The ebpf-client-sdk currently runs [bpftool](https://github.com/libbpf/bpftool) underneath and has output a parsed btf which we can use in the next step to program the maps.

the contents of the file generated are,

```
$ cat infw_parsed.btf.json
{
 "maps": [
  {
   "size": 32,
   "name": "ingress_node_firewall_events_map",
   "key": {
    "name": "(anon)",
    "kind": "PTR",
    "type": {
     "name": "__u32",
     "kind": "TYPEDEF",
     "type": {
      "name": "unsigned int",
      "kind": "INT",
      "id": 8,
      "size": 4,
      "bits_offset": 0,
      "nr_bits": 32,
      "encoding": "(none)"
     }
    },
    "flatten": {
     "type_name": "unsigned int",
     "size": 4,
     "kind": "INT",
     "input": null
    }
   },
   "value": {
    "name": "(anon)",
    "kind": "PTR",
    "type": {
     "name": "__u32",
     "kind": "TYPEDEF",
     "type": {
      "name": "unsigned int",
      "kind": "INT",
      "id": 8,
      "size": 4,
      "bits_offset": 0,
      "nr_bits": 32,
      "encoding": "(none)"
     }
    },
    "flatten": {
     "type_name": "unsigned int",
     "size": 4,
     "kind": "INT",
     "input": null
    }
   }
  },
  {
   "size": 32,
   "name": "ingress_node_firewall_statistics_map",
   "key": {
    "name": "(anon)",
    "kind": "PTR",
    "type": {
     "name": "__u32",
     "kind": "TYPEDEF",
     "type": {
      "name": "unsigned int",
      "kind": "INT",
      "id": 8,
      "size": 4,
      "bits_offset": 0,
      "nr_bits": 32,
      "encoding": "(none)"
     }
    },
    "flatten": {
     "type_name": "unsigned int",
     "size": 4,
     "kind": "INT",
     "input": null
    }
   },
   "value": {
    "name": "(anon)",
    "kind": "PTR",
    "type": {
     "name": "ruleStatistics_st",
     "kind": "STRUCT",
     "members": [
      {
       "name": "allow_stats",
       "type": {
        "name": "allow_stats_st",
        "kind": "STRUCT",
        "members": [
         {
          "name": "packets",
          "type": {
           "name": "__u64",
           "kind": "TYPEDEF",
           "type": {
            "name": "long long unsigned int",
            "kind": "INT",
            "id": 19,
            "size": 8,
            "bits_offset": 0,
            "nr_bits": 64,
            "encoding": "(none)"
           }
          }
         },
         {
          "name": "bytes",
          "type": {
           "name": "__u64",
           "kind": "TYPEDEF",
           "type": {
            "name": "long long unsigned int",
            "kind": "INT",
            "id": 19,
            "size": 8,
            "bits_offset": 0,
            "nr_bits": 64,
            "encoding": "(none)"
           }
          }
         }
        ]
       }
      },
      {
       "name": "deny_stats",
       "type": {
        "name": "deny_stats_st",
        "kind": "STRUCT",
        "members": [
         {
          "name": "packets",
          "type": {
           "name": "__u64",
           "kind": "TYPEDEF",
           "type": {
            "name": "long long unsigned int",
            "kind": "INT",
            "id": 19,
            "size": 8,
            "bits_offset": 0,
            "nr_bits": 64,
            "encoding": "(none)"
           }
          }
         },
         {
          "name": "bytes",
          "type": {
           "name": "__u64",
           "kind": "TYPEDEF",
           "type": {
            "name": "long long unsigned int",
            "kind": "INT",
            "id": 19,
            "size": 8,
            "bits_offset": 0,
            "nr_bits": 64,
            "encoding": "(none)"
           }
          }
         }
        ]
       }
      }
     ]
    },
    "flatten": {
     "variable_name": "ruleStatistics_st",
     "kind": "STRUCT",
     "member": [
      {
       "variable_name": "allow_stats_st",
       "kind": "STRUCT",
       "member": [
        {
         "variable_name": "packets",
         "type_name": "long long unsigned int",
         "size": 8,
         "kind": "INT",
         "input": null
        },
        {
         "variable_name": "bytes",
         "type_name": "long long unsigned int",
         "size": 8,
         "kind": "INT",
         "input": null
        }
       ]
      },
      {
       "variable_name": "deny_stats_st",
       "kind": "STRUCT",
       "member": [
        {
         "variable_name": "packets",
         "type_name": "long long unsigned int",
         "size": 8,
         "kind": "INT",
         "input": null
        },
        {
         "variable_name": "bytes",
         "type_name": "long long unsigned int",
         "size": 8,
         "kind": "INT",
         "input": null
        }
       ]
      }
     ]
    }
   }
  },
  {
   "size": 48,
   "name": "ingress_node_firewall_table_map",
   "key": {
    "name": "(anon)",
    "kind": "PTR",
    "type": {
     "name": "lpm_ip_key_st",
     "kind": "STRUCT",
     "members": [
      {
       "name": "prefixLen",
       "type": {
        "name": "__u32",
        "kind": "TYPEDEF",
        "type": {
         "name": "unsigned int",
         "kind": "INT",
         "id": 8,
         "size": 4,
         "bits_offset": 0,
         "nr_bits": 32,
         "encoding": "(none)"
        }
       }
      },
      {
       "name": "ingress_ifindex",
       "type": {
        "name": "__u32",
        "kind": "TYPEDEF",
        "type": {
         "name": "unsigned int",
         "kind": "INT",
         "id": 8,
         "size": 4,
         "bits_offset": 0,
         "nr_bits": 32,
         "encoding": "(none)"
        }
       }
      },
      {
       "name": "ip_data",
       "type": {
        "name": "(anon)",
        "kind": "ARRAY",
        "type": {
         "name": "__u8",
         "kind": "TYPEDEF",
         "type": {
          "name": "unsigned char",
          "kind": "INT",
          "id": 31,
          "size": 1,
          "bits_offset": 0,
          "nr_bits": 8,
          "encoding": "(none)"
         }
        }
       }
      }
     ]
    },
    "flatten": {
     "variable_name": "lpm_ip_key_st",
     "kind": "STRUCT",
     "member": [
      {
       "variable_name": "prefixLen",
       "type_name": "unsigned int",
       "size": 4,
       "kind": "INT",
       "input": null
      },
      {
       "variable_name": "ingress_ifindex",
       "type_name": "unsigned int",
       "size": 4,
       "kind": "INT",
       "input": null
      },
      {
       "variable_name": "ip_data",
       "kind": "ARRAY",
       "input": [],
       "member": {
        "type_name": "unsigned char",
        "size": 1,
        "kind": "INT",
        "input": null
       }
      }
     ]
    }
   },
   "value": {
    "name": "(anon)",
    "kind": "PTR",
    "type": {
     "name": "rulesVal_st",
     "kind": "STRUCT",
     "members": [
      {
       "name": "rules",
       "type": {
        "name": "(anon)",
        "kind": "ARRAY",
        "type": {
         "name": "ruleType_st",
         "kind": "STRUCT",
         "members": [
          {
           "name": "ruleId",
           "type": {
            "name": "__u32",
            "kind": "TYPEDEF",
            "type": {
             "name": "unsigned int",
             "kind": "INT",
             "id": 8,
             "size": 4,
             "bits_offset": 0,
             "nr_bits": 32,
             "encoding": "(none)"
            }
           }
          },
          {
           "name": "protocol",
           "type": {
            "name": "__u8",
            "kind": "TYPEDEF",
            "type": {
             "name": "unsigned char",
             "kind": "INT",
             "id": 31,
             "size": 1,
             "bits_offset": 0,
             "nr_bits": 8,
             "encoding": "(none)"
            }
           }
          },
          {
           "name": "dstPortStart",
           "type": {
            "name": "__u16",
            "kind": "TYPEDEF",
            "type": {
             "name": "unsigned short",
             "kind": "INT",
             "id": 37,
             "size": 2,
             "bits_offset": 0,
             "nr_bits": 16,
             "encoding": "(none)"
            }
           }
          },
          {
           "name": "dstPortEnd",
           "type": {
            "name": "__u16",
            "kind": "TYPEDEF",
            "type": {
             "name": "unsigned short",
             "kind": "INT",
             "id": 37,
             "size": 2,
             "bits_offset": 0,
             "nr_bits": 16,
             "encoding": "(none)"
            }
           }
          },
          {
           "name": "icmpType",
           "type": {
            "name": "__u8",
            "kind": "TYPEDEF",
            "type": {
             "name": "unsigned char",
             "kind": "INT",
             "id": 31,
             "size": 1,
             "bits_offset": 0,
             "nr_bits": 8,
             "encoding": "(none)"
            }
           }
          },
          {
           "name": "icmpCode",
           "type": {
            "name": "__u8",
            "kind": "TYPEDEF",
            "type": {
             "name": "unsigned char",
             "kind": "INT",
             "id": 31,
             "size": 1,
             "bits_offset": 0,
             "nr_bits": 8,
             "encoding": "(none)"
            }
           }
          },
          {
           "name": "action",
           "type": {
            "name": "__u8",
            "kind": "TYPEDEF",
            "type": {
             "name": "unsigned char",
             "kind": "INT",
             "id": 31,
             "size": 1,
             "bits_offset": 0,
             "nr_bits": 8,
             "encoding": "(none)"
            }
           }
          }
         ]
        }
       }
      }
     ]
    },
    "flatten": {
     "variable_name": "rulesVal_st",
     "kind": "STRUCT",
     "member": [
      {
       "variable_name": "rules",
       "kind": "ARRAY",
       "input": [],
       "member": {
        "variable_name": "ruleType_st",
        "kind": "STRUCT",
        "member": [
         {
          "variable_name": "ruleId",
          "type_name": "unsigned int",
          "size": 4,
          "kind": "INT",
          "input": null
         },
         {
          "variable_name": "protocol",
          "type_name": "unsigned char",
          "size": 1,
          "kind": "INT",
          "input": null
         },
         {
          "variable_name": "dstPortStart",
          "type_name": "unsigned short",
          "size": 2,
          "kind": "INT",
          "input": null
         },
         {
          "variable_name": "dstPortEnd",
          "type_name": "unsigned short",
          "size": 2,
          "kind": "INT",
          "input": null
         },
         {
          "variable_name": "icmpType",
          "type_name": "unsigned char",
          "size": 1,
          "kind": "INT",
          "input": null
         },
         {
          "variable_name": "icmpCode",
          "type_name": "unsigned char",
          "size": 1,
          "kind": "INT",
          "input": null
         },
         {
          "variable_name": "action",
          "type_name": "unsigned char",
          "size": 1,
          "kind": "INT",
          "input": null
         }
        ]
       }
      }
     ]
    }
   }
  }
 ]
}
```

Currently ebpf-client-sdk needs to be explicitly told about location of the maps which you can do so by running.

```
$ python3 ebpf-sdk-cli.py --parsed_btf ./infw_parsed.btf.json --op enrich
2023-02-13:14:56:25,155 INFO [ebpf-sdk-cli.py:149] Welcome to ebpf-client-sdk-cli
2023-02-13:14:56:25,156 INFO [ebpf-sdk-cli.py:72] First we need to know where maps are
2023-02-13:14:56:25,156 INFO [ebpf-sdk-cli.py:74] Please tell the pinned location of the map - ingress_node_firewall_events_map
Please tell the pinned location of the map - ingress_node_firewall_events_map
/sys/fs/bpf/ingress_node_firewall_table_map
2023-02-13:14:58:15,791 INFO [ebpf-sdk-cli.py:74] Please tell the pinned location of the map - ingress_node_firewall_statistics_map
Please tell the pinned location of the map - ingress_node_firewall_statistics_map
n/a
2023-02-13:15:02:59,917 INFO [ebpf-sdk-cli.py:74] Please tell the pinned location of the map - ingress_node_firewall_table_map
Please tell the pinned location of the map - ingress_node_firewall_table_map
n/a
2023-02-13:15:03:01,893 INFO [ebpf-sdk-cli.py:76] Thanks
```

The two statistics maps are not focused right now so we just enter `n/a` while for firewall table map we enter correct path `/sys/fs/bpf/ingress_node_firewall_table_map`

## Programming the map.

First we need to setup an environment to load the program and testing. Here because this program uses xdp connection, i'm just going to create a veth pair
with one veth inside a namespace and attach the program to the veth in root namespace so we can send traffic from inside the namespace to outside emulating a pod.

```
    ip netns add vns1
    ip link add veth type veth peer name vpeer
    ip link set vpeer netns vns1
    ip addr add 10.10.10.1/24 dev veth
    ip link set veth up
    ip netns exec vns1 ip link set lo up
    ip netns exec vns1 ip link set vpeer up
    ip netns exec vns1 ip addr add 10.10.10.2/24 dev vpeer
    ip netns exec vns1 ip route add 10.10.10.1 dev vpeer
    ip netns exec vns1 ip route add default via 10.10.10.1
```

Now we load and attach the infw firewall to the root `veth` port.

```
$ bpftool prog loadall ingress_node_firewall_kernel.o /sys/fs/bpf/xdp/ingress_node_firewall type xdp -d
$ bpftool net attach xdp id <prog-id> dev veth
```

