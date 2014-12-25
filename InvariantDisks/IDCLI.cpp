//
//  IDCLI.cpp
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
#include "IDDiskArbitrationDispatcher.hpp"
#include "IDDiskInfoLogger.hpp"
#include "IDDAHandlerIdle.hpp"
#include "IDMediaPathLinker.hpp"
#include "IDUUIDLinker.hpp"
#include "IDSerialLinker.hpp"
#include "IDDispatchUtils.hpp"

#include <vector>
#include <map>
#include <string>
#include <iostream>
#include <algorithm>
#include <thread>
#include <functional>

#include <CoreFoundation/CoreFoundation.h>

#include <dispatch/dispatch.h>

#include "git-version.h"

namespace ID
{
	struct CLI::Impl
	{
		std::mutex mutex;
		DispatchSource signalSourceINT;
		DispatchSource signalSourceTERM;
		bool showHelp = false;
		bool verbose = false;
		std::string basePath = "/var/run/disk";
		int64_t idleTimeoutNS = 4000000000;
		CFRunLoopRef runloop = nullptr;
	};

	CLI::CLI(int & argc, char ** argv) :
		m_impl(new Impl)
	{
		// Setup
		dispatch_function_t stopHandler = [](void * ctx){ static_cast<CLI*>(ctx)->stop();};
		m_impl->signalSourceINT = createSourceSignal(SIGINT, this, stopHandler);
		m_impl->signalSourceTERM = createSourceSignal(SIGTERM, this, stopHandler);
		// UI
		std::cout << "InvariantDisk " << GIT_VERSION << std::endl;
		parse(argc, argv);
	}

	CLI::~CLI()
	{
	}

	int CLI::exec()
	{
		{
			std::lock_guard<std::mutex> lock(m_impl->mutex);
			if (m_impl->runloop)
				throw Exception("CLI already running");
			m_impl->runloop = CFRunLoopGetCurrent();
		}
		DiskArbitrationDispatcher dispatcher;
		dispatcher.addHandler(std::make_shared<DAHandlerIdle>(m_impl->basePath, m_impl->idleTimeoutNS));
		dispatcher.addHandler(std::make_shared<DiskInfoLogger>(std::cout, m_impl->verbose));
		dispatcher.addHandler(std::make_shared<MediaPathLinker>(m_impl->basePath + "/by-path"));
		dispatcher.addHandler(std::make_shared<UUIDLinker>(m_impl->basePath + "/by-id"));
		dispatcher.addHandler(std::make_shared<SerialLinker>(m_impl->basePath + "/by-serial"));
		dispatcher.start();
		CFRunLoopRun();
		{
			std::lock_guard<std::mutex> lock(m_impl->mutex);
			m_impl->runloop = nullptr;
		}
		return 0;
	}

	void CLI::stop()
	{
		std::lock_guard<std::mutex> lock(m_impl->mutex);
		if (m_impl->runloop)
			CFRunLoopStop(m_impl->runloop);
	}

	struct CLIFlagHandler
	{
		size_t argCount;
		std::function<void(char **)> func;
	};

	void CLI::parse(int & argc, char ** argv)
	{
		// Command Line Parsing
		std::map<std::string, CLIFlagHandler> cliFlags =
		{
			{"-h", { 0, [&](char **){ m_impl->showHelp = true; }}},
			{"-v", { 0, [&](char **){ m_impl->verbose = true; }}},
			{"-p", { 1, [&](char ** a){ m_impl->basePath = a[1]; }}},
			{"-t", { 1, [&](char ** a){
				try
				{
					m_impl->idleTimeoutNS = std::stol(a[1])*1000000;
				}
				catch (...)
				{
					Throw<Exception>() << "Idle Timeout " << a[1] << " is not a number";
				}
				if (m_impl->idleTimeoutNS < 0)
					Throw<Exception>() << "Idle Timeout " << a[1] << " is out of range";
			}}}
		};
		for (int argIdx = 0; argIdx < argc; ++argIdx)
		{
			auto flagIt = cliFlags.find(argv[argIdx]);
			if (flagIt != cliFlags.end())
			{
				CLIFlagHandler const & f = flagIt->second;
				if (argIdx + f.argCount >= argc)
					Throw<Exception>() << "Flag " << argv[argIdx] << " requires " << f.argCount << " arguments";
				f.func(&argv[argIdx]);
				argIdx += f.argCount;
			}
		}
	}
}
