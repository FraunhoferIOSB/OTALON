Set(FETCHCONTENT_QUIET FALSE)
set(PYBIND11_FINDPYTHON NEW)
include(FetchContent)
FetchContent_Declare(
    pybind11
    GIT_REPOSITORY https://github.com/pybind/pybind11
    GIT_TAG        v3.0.1
)
FetchContent_MakeAvailable(pybind11)