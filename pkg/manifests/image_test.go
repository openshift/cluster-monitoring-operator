// Copyright 2018 The Cluster Monitoring Operator Authors
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

package manifests

import (
	"testing"
)

func TestImageParsing(t *testing.T) {
	imageCases := []struct {
		str   string
		image image
	}{
		{
			str: "quay.io/test/image:tag",
			image: image{
				repo: "quay.io/test/image",
				tag:  "tag",
			},
		}, {
			str: "image:tag",
			image: image{
				repo: "image",
				tag:  "tag",
			},
		}, {
			str: "quay.io:443/test/image:tag",
			image: image{
				repo: "quay.io:443/test/image",
				tag:  "tag",
			},
		},
	}

	for _, imageCase := range imageCases {
		image, err := imageFromString(imageCase.str)
		if err != nil {
			t.Errorf("error parsing image string %s : %v", imageCase.str, err)
			continue
		}
		if imageCase.image != *image {
			t.Errorf("parsed image %+v does not match expected image %+v", *image, imageCase.image)
			continue
		}
		if imageCase.str != image.String() {
			t.Errorf("parsed image string %s does not match expected image string %s", image.String(), imageCase.str)
		}
	}
}
