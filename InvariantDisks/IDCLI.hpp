//
//  IDCLI.hpp
//  InvariantDisks
//
//  Created by cbreak on 2014.04.27.
//  Copyright (c) 2014 the-color-black.net. All rights reserved.
//

#ifndef ID_CLI_HPP
#define ID_CLI_HPP

#include <iostream>
#include <string>
#include <memory>

namespace ID
{
	class CLI
	{
	public:
		CLI(int & argc, char ** argv);
		~CLI();

	public:
		int exec();
		void stop();

	private:
		void parse(int & argc, char ** argv);

	private:
		struct Impl;
		std::unique_ptr<Impl> m_impl;
	};
}

#endif
