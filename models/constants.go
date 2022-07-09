/*
Copyright © 2022 THINKINGATOMS LLC <atom@thinkingatoms.com>
*/

package models

//goland:noinspection GoSnakeCaseUsage
const DEFAULT_ROOT_NAME string = "APP"

type ctxRequestKey int

const (
	_ ctxRequestKey = iota
	RequestAuthKey
)
