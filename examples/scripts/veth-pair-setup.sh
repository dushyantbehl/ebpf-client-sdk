#!/bin/bash

VETH_ROOT_NAME=veth
VETH_NS_NAME=vpeer
NS=vns1
VETH_ROOT_IP=10.10.10.1
VETH_NS_IP=10.10.10.2

ip netns add ${NS}
ip link add ${VETH_ROOT_NAME} type ${VETH_ROOT_NAME} peer name ${VETH_NS_NAME}
ip link set ${VETH_NS_NAME} netns ${NS}
ip addr add ${VETH_ROOT_IP}/24 dev ${VETH_ROOT_NAME}
ip link set ${VETH_ROOT_NAME} up
ip netns exec ${NS} ip link set lo up
ip netns exec ${NS} ip link set ${VETH_NS_NAME} up
ip netns exec ${NS} ip addr add ${VETH_NS_IP}/24 dev ${VETH_NS_NAME}
ip netns exec ${NS} ip route add ${VETH_ROOT_IP} dev ${VETH_NS_NAME}
ip netns exec ${NS} ip route add default via ${VETH_ROOT_IP}