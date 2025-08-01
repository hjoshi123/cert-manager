/*
Copyright The cert-manager Authors.

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

// Code generated by applyconfiguration-gen. DO NOT EDIT.

package v1

import (
	certmanagerv1 "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
)

// CertificatePrivateKeyApplyConfiguration represents a declarative configuration of the CertificatePrivateKey type for use
// with apply.
type CertificatePrivateKeyApplyConfiguration struct {
	RotationPolicy *certmanagerv1.PrivateKeyRotationPolicy `json:"rotationPolicy,omitempty"`
	Encoding       *certmanagerv1.PrivateKeyEncoding       `json:"encoding,omitempty"`
	Algorithm      *certmanagerv1.PrivateKeyAlgorithm      `json:"algorithm,omitempty"`
	Size           *int                                    `json:"size,omitempty"`
}

// CertificatePrivateKeyApplyConfiguration constructs a declarative configuration of the CertificatePrivateKey type for use with
// apply.
func CertificatePrivateKey() *CertificatePrivateKeyApplyConfiguration {
	return &CertificatePrivateKeyApplyConfiguration{}
}

// WithRotationPolicy sets the RotationPolicy field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the RotationPolicy field is set to the value of the last call.
func (b *CertificatePrivateKeyApplyConfiguration) WithRotationPolicy(value certmanagerv1.PrivateKeyRotationPolicy) *CertificatePrivateKeyApplyConfiguration {
	b.RotationPolicy = &value
	return b
}

// WithEncoding sets the Encoding field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the Encoding field is set to the value of the last call.
func (b *CertificatePrivateKeyApplyConfiguration) WithEncoding(value certmanagerv1.PrivateKeyEncoding) *CertificatePrivateKeyApplyConfiguration {
	b.Encoding = &value
	return b
}

// WithAlgorithm sets the Algorithm field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the Algorithm field is set to the value of the last call.
func (b *CertificatePrivateKeyApplyConfiguration) WithAlgorithm(value certmanagerv1.PrivateKeyAlgorithm) *CertificatePrivateKeyApplyConfiguration {
	b.Algorithm = &value
	return b
}

// WithSize sets the Size field in the declarative configuration to the given value
// and returns the receiver, so that objects can be built by chaining "With" function invocations.
// If called multiple times, the Size field is set to the value of the last call.
func (b *CertificatePrivateKeyApplyConfiguration) WithSize(value int) *CertificatePrivateKeyApplyConfiguration {
	b.Size = &value
	return b
}
