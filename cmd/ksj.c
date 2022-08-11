// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (c) 2022 CoAsia Nexell, Inc
 * Written by Sukjin Kong <sjkong@coasia.com>
 */

#include <stdio.h>
#include <command.h>

static int ksj_ub(struct cmd_tbl *cmdtp, int flag, int argc, char *const argv[])
{
	if(argc != 2)
    {
	    return CMD_RET_FAILURE;
    }
    
    printf("%s\n", __func__);

	return CMD_RET_SUCCESS;
}

U_BOOT_CMD(
	ksj, 2, 1, ksj_ub,
	"usage",
	"help"
);