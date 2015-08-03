//
//  main.cpp
//  InvariantDisks
//
//  Created by Gerhard Röthlin on 2014.04.27.
//  Copyright (c) 2014 the-color-black.net. All rights reserved.
//
//  Redistribution and use in source and binary forms, with or without modification, are permitted
//  provided that the conditions of the "3-Clause BSD" license described in the BSD.LICENSE file are met.
//  Additional licensing options are described in the README file.
//

#include "IDCLI.hpp"
#include "IDException.hpp"

#include <asl.h>
#include <iostream>

int main(int argc, char ** argv)
{
	try
	{
		ID::CLI idCommandLine(argc, argv);
		return idCommandLine.exec();
	}
	catch (ID::Exception const & e)
	{
		asl_log(0, 0, ASL_LEVEL_CRIT, "%s", e.what());
		std::cerr << e.what() << std::endl;
	}
	catch (std::exception const & e)
	{
		asl_log(0, 0, ASL_LEVEL_CRIT, "Terminated by exception: %s", e.what());
		std::cerr << "Terminated by exception: " << e.what() << std::endl;
	}
	catch (...)
	{
		asl_log(0, 0, ASL_LEVEL_CRIT, "Terminated by unknown exception");
		std::cerr << "Terminated by unknown exception" << std::endl;
	}
	return -1;
}
