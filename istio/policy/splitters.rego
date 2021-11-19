package main

deny[msg] {
	input.kind == "VirtualService"
	current := input.spec.http[0].route[0].destination.host
	canary := input.spec.http[0].route[1].destination.host
	not current == canary
	msg := "Current and Canary hosts should be same"
}

deny[msg] {
	input.kind == "VirtualService"
	current := input.spec.http[0].route[0].destination.weight
	canary := input.spec.http[0].route[1].destination.weight
	sumSplitter := current + canary
    sumSplitter > 100
	msg:="Service Splitters can't be greater than 100"
}