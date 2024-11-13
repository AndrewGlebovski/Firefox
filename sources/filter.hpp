/**
 * \file
 * \brief Contains filter function declaration.
*/

#pragma once

// ============================================================================

#include <list.hpp>

// ============================================================================

/// Filters packet from 'in' socket to 'out' socket based on rules from list.
/// Returns true if package passed.
bool Filter(int in, int out, const List& list);

/// Creates and binds raw socket with specific interface.
/// Note: socket will accept ip packages only.
int CreateSocket(const char* if_name);
