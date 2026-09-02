package cmd

import "errors"

var errTODO = errors.New("not implemented")

func Get(args []string) error    { return errTODO }
func Reveal(args []string) error { return errTODO }
func List(args []string) error   { return errTODO }
func Run(args []string) error    { return errTODO }
func Export(args []string) error { return errTODO }
func Import(args []string) error { return errTODO }
