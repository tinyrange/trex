"""Assertions and suite execution for trex Starlark tests."""

def equal(got, want, message = ""):
    """Fails when got and want differ."""
    if got != want:
        fail(message or "got {}, want {}".format(repr(got), repr(want)))

def not_equal(got, unwanted, message = ""):
    """Fails when got equals unwanted."""
    if got == unwanted:
        fail(message or "unexpected value {}".format(repr(got)))

def true(value, message = ""):
    """Fails when value is false."""
    if not value:
        fail(message or "expected a true value, got {}".format(repr(value)))

def false(value, message = ""):
    """Fails when value is true."""
    if value:
        fail(message or "expected a false value, got {}".format(repr(value)))

def contains(container, value, message = ""):
    """Fails when container does not contain value."""
    if value not in container:
        fail(message or "{} does not contain {}".format(repr(container), repr(value)))

def raises(callback, args = [], kwargs = {}, message = ""):
    """Returns an expected error string or fails when callback succeeds."""
    result = testing.attempt(callback, args = args, kwargs = kwargs)
    if result.ok:
        fail("expected callback to fail")
    if message and message not in result.error:
        fail("error {} does not contain {}".format(repr(result.error), repr(message)))
    return result.error

def case(name, callback):
    """Returns one named test case."""
    if not name or callback == None:
        fail("test case requires a name and callback")
    return {"name": name, "callback": callback}

def suite(name, cases):
    """Returns one named collection of test cases."""
    if not name:
        fail("test suite requires a name")
    return {"name": name, "cases": cases}

def run(suites, pattern = ""):
    """Runs selected suites and fails after reporting every failed case."""
    selected = 0
    failures = []
    for group in suites:
        for item in group["cases"]:
            name = group["name"] + "/" + item["name"]
            if pattern and pattern.lower() not in name.lower():
                continue
            selected += 1
            result = testing.attempt(item["callback"])
            if result.ok:
                print("PASS", name)
            else:
                print("FAIL", name, result.error)
                failures.append(name + ": " + result.error)
    if selected == 0:
        fail("no Starlark tests matched " + repr(pattern))
    print("Starlark tests:", selected - len(failures), "passed,", len(failures), "failed")
    if failures:
        fail("\n".join(failures))
