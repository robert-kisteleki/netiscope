package measurements

// ResultCode to help enumerate outcomes of a measurement
type ResultCode int

// result codes and indexes into a MultipeResult
const (
	ResultSuccess ResultCode = 0
	ResultPartial ResultCode = 1
	ResultFailure ResultCode = 2
)

// MultipleResult stores a tuple of successful/partial/fail
type MultipleResult [3]int
