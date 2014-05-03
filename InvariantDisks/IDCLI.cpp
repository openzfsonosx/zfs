//
//  IDCLI.cpp
//  InvariantDisks
//
//  Created by Gerhard Röthlin on 2014.04.27.
//  Copyright (c) 2014 the-color-black.net. All rights reserved.
//
//  Redistribution and use in source and binary forms, with or without modification, are permitted
//  provided that the conditions of the "3-Clause BSD" license described in the LICENSE file are met.
//

#include "IDCLI.hpp"

#include "IDException.hpp"
#include "IDDiskArbitrationDispatcher.hpp"
#include "IDDiskInfoLogger.hpp"
#include "IDMediaPathLinker.hpp"
#include "IDUUIDLinker.hpp"
#include "IDSerialLinker.hpp"

#include <vector>
#include <string>
#include <iostream>
#include <algorithm>
#include <thread>

#include <CoreFoundation/CoreFoundation.h>

#include <dispatch/dispatch.h>

#include "git-version.h"

namespace ID
{
	struct DispatchDelete
	{
		void operator()(dispatch_source_s * source)
		{
			dispatch_source_set_event_handler_f(source, nullptr);
			dispatch_release(source);
		}
	};

	typedef std::unique_ptr<dispatch_source_s, DispatchDelete> DispatchSource;

	DispatchSource createSourceSignal(int sig, void * ctx)
	{
		signal(sig, SIG_IGN);
		dispatch_source_t source = dispatch_source_create(DISPATCH_SOURCE_TYPE_SIGNAL, sig, 0,
														  DISPATCH_TARGET_QUEUE_DEFAULT);
		dispatch_set_context(source, ctx);
		dispatch_source_set_event_handler_f(source,
			[](void * ctx){ static_cast<CLI*>(ctx)->stop();});
		dispatch_resume(source);
		return DispatchSource(source);
	}

	struct CLI::Impl
	{
		std::mutex mutex;
		DispatchSource signalSourceINT;
		DispatchSource signalSourceTERM;
		bool showHelp = false;
		std::string basePath = "/var/run/disk";
		CFRunLoopRef runloop = nullptr;
	};

	CLI::CLI(int & argc, char ** argv) :
		m_impl(new Impl)
	{
		// Setup
		m_impl->signalSourceINT = createSourceSignal(SIGINT, this);
		m_impl->signalSourceTERM = createSourceSignal(SIGTERM, this);
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
		dispatcher.addHandler(std::make_shared<DiskInfoLogger>(std::cout));
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

	void CLI::parse(int & argc, char ** argv)
	{
		std::vector<std::string> args(argv, argv + argc);
		// -h
		if (std::count(args.begin(), args.end(), "-h"))
			m_impl->showHelp = true;
		// -p
		auto p = std::find(args.begin(), args.end(), "-p");
		if (p != args.end())
		{
			++p;
			if (p == args.end())
				throw Exception("-p <path> requires a path argument");
			m_impl->basePath = *p;
		}
	}
}
