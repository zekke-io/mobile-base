package zekke.core.primitives

class PrimitiveFailureException(val operation: String) : RuntimeException("$operation failed")
