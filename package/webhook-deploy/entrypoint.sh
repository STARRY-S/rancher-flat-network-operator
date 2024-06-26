#!/bin/bash

set -euo pipefail

secret=${secret:-"rancher-flat-network-webhook-certs"}

if [[ ${IS_MULTUS_INIT_CONTAINER:-} != "" ]]; then
    # Running as multus init container.
    echo "Start delete multus auto generated CNI config:"
    ls -al /host/etc/cni/net.d/00-multus.conf*
    rm /host/etc/cni/net.d/00-multus.conf*
    echo "Done"
    exit 0
fi

if [[ ${IS_OPERATOR_INIT_CONTAINER:-} != "" ]]; then
    # Running as operator init container.
    echo "Waiting for secret 'kube-system/${secret}' created..."
    while !kubectl -n kube-system get secret $secret &> /dev/null
    do
        sleep 2
    done
    exit 0
fi

echo "Generating rancher-flat-network-operator webhook TLS secrets..."
./webhook-create-signed-cert.sh
echo

if [[ ${ROLLOUT_FLATNETWORK_DEPLOYMENT:-} = "true" ]] && kubectl get deployment rancher-flat-network-operator &> /dev/null
then
    echo "Restart rancher-flat-network-operator deployment..."
    kubectl -n kube-system rollout restart deployment/rancher-flat-network-operator
    echo
fi

echo "Deploying flatnetwork operator validating webhook configurations..."
cat ./validating-webhook.yaml | /webhook-patch-ca-bundle.sh | kubectl apply -f -
echo

echo "Successfully setup rancher-flat-network-operator webhook configurations..."
exit 0
