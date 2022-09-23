/*
Copyright 2021 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"time"

	"github.com/cespare/xxhash"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/kpng/client"
	"sigs.k8s.io/kpng/client/lightdiffstore"
)

var state *lightdiffstore.DiffStore = lightdiffstore.New()

func main() {
	client.Run(printState)
}

func printState(items []*client.ServiceEndpoints) {
	fmt.Println("# ------------------------------------------------------------------------")
	fmt.Println("#", time.Now())
	fmt.Println("#")

	for _, item := range items {
		state.Reset(lightdiffstore.ItemChanged)
		svcUniqueName := types.NamespacedName{Name: item.Service.Name, Namespace: item.Service.Namespace}

		for _, port := range item.Service.Ports {
			svcKey := fmt.Sprintf("%s/%d/%s", svcUniqueName, port.Port, port.Protocol)

			// JSON encoding of our services + EP information
			svcEndptRelationBytes := new(bytes.Buffer)
			json.NewEncoder(svcEndptRelationBytes).Encode(item)
			state.Set([]byte(svcKey), xxhash.Sum64(svcEndptRelationBytes.Bytes()), item)
		}
	}

	fmt.Printf("Number of Events: %d\nNumber of Backend Relevant update/create Events: %d\n", len(items), len(state.Updated()))
}
