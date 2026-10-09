package diff

import (
	"fmt"

	"github.com/pgplex/pgschema/ir"
)

func ExecutionIdentity(d Diff) string {
	switch source := d.Source.(type) {
	case *ir.Function:
		return functionExecutionIdentity(source)
	case *functionDiff:
		return functionExecutionIdentity(source.Old)
	case *ir.Procedure:
		return procedureExecutionIdentity(source)
	case *procedureDiff:
		return procedureExecutionIdentity(source.Old)
	case *ir.Aggregate:
		return aggregateExecutionIdentity(source)
	case *aggregateDiff:
		return aggregateExecutionIdentity(source.Old)
	default:
		return ""
	}
}

func functionExecutionIdentity(function *ir.Function) string {
	if function == nil {
		return ""
	}
	return fmt.Sprintf("%s.%s(%s)", function.Schema, function.Name, function.GetArguments())
}

func procedureExecutionIdentity(procedure *ir.Procedure) string {
	if procedure == nil {
		return ""
	}
	return fmt.Sprintf("%s.%s(%s)", procedure.Schema, procedure.Name, procedure.GetArguments())
}

func aggregateExecutionIdentity(aggregate *ir.Aggregate) string {
	if aggregate == nil {
		return ""
	}
	return fmt.Sprintf("%s.%s(%s)", aggregate.Schema, aggregate.Name, aggregateArgs(aggregate.Arguments))
}
