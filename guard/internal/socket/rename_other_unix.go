// SPDX-License-Identifier: MIT
//go:build unix && !darwin && !linux

package socket

import "errors"

func renameNoReplace(int, string, string) error {
	return errors.New("socket: safe cleanup unsupported on this Unix platform")
}
