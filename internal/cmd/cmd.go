// Package cmd implements the kleidos verbs. Each entry point takes the argument
// list following the verb and returns an error whose exit status errs.Code
// resolves.
package cmd

import "errors"

var errTODO = errors.New("not implemented")

func Set(args []string) error    { return errTODO }
func Get(args []string) error    { return errTODO }
func Reveal(args []string) error { return errTODO }
func List(args []string) error   { return errTODO }
func Delete(args []string) error { return errTODO }
func Rename(args []string) error { return errTODO }
func Run(args []string) error    { return errTODO }
func Export(args []string) error { return errTODO }
func Import(args []string) error { return errTODO }
