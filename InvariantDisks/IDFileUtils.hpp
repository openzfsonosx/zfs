//
//  IDFileUtils.hpp
//  InvariantDisks
//
//  Created by Gerhard Röthlin on 2014.04.27.
//  Copyright (c) 2014 the-color-black.net. All rights reserved.
//
//  Redistribution and use in source and binary forms, with or without modification, are permitted
//  provided that the conditions of the "3-Clause BSD" license described in the LICENSE file are met.
//

#ifndef ID_FILEUTILS_HPP
#define ID_FILEUTILS_HPP

#include <string>

namespace ID
{
	void createPath(std::string const & path);
	void createSymlink(std::string const & link, std::string const & target);
	void removeSymlink(std::string const & link);
}

#endif
