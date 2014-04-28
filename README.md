InvariantDisks
================

InvariantDisks is a small program maintaining a mapping from invariant labels to the potentially
varying /dev/diskXsY entries. At the moment only the media path is used to create links. It is
independent from detection order and relies on the location in the hardware. Alternative methods
such as GUID/UUID/Serial based methods are planed.

The Problem and some solutions on Linux are described on
http://zfsonlinux.org/faq.html#WhatDevNamesShouldIUseWhenCreatingMyPool

License
=======

This program is licensed under the "3-clause BSD" License. See the LICENSE.md file for details.
