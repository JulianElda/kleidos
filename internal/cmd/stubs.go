package cmd

import "errors"

var errTODO = errors.New("not implemented")

func Run(args []string) error    { return errTODO }
func Import(args []string) error { return errTODO }
