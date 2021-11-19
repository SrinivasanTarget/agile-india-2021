package main

deny[msg] {
	input.kind == "Deployment"
	imageName := input.spec.template.spec.containers[_].image
	contains(lower(imageName), ":latest")
	msg := "image should not be tag with latest"
}

deny[msg] {
	input.kind == "Deployment"
	input.spec.template.spec.securityContext.privileged == true
	msg := "container should not run as root privileged"
}