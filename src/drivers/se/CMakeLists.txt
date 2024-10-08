px4_add_git_submodule(TARGET git_se_devices PATH "devices")

px4_add_module(
	MODULE drivers_se
	MAIN se
	SRCS
		se.cpp
		se.h
	MODULE_CONFIG
		module.yaml
	DEPENDS
	)
