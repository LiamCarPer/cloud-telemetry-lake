from typing import Iterable, Dict, Any, List

def parse_stream(stream_iterable: Iterable[Dict[str, Any]], middleware_stack: List[Any]) -> Iterable[Dict[str, Any]]:
    """
    Process a stream of parsed log records through a stack of middlewares.
    
    Args:
        stream_iterable: An iterable of parsed log dictionaries (e.g., from parser.parse()).
        middleware_stack: A list of middleware objects that implement an `analyze(row: dict) -> dict` method.
        
    Yields:
        The processed log records.
    """
    for row in stream_iterable:
        if row.get("error"):
            # Skip middleware processing for unparsed/error rows
            yield row
            continue
            
        # Process through each middleware in the stack
        for middleware in middleware_stack:
            row = middleware.analyze(row)
            
        yield row
