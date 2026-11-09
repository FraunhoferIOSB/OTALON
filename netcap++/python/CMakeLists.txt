python_add_library(_core MODULE py_network_capture.cpp WITH_SOABI)
target_link_libraries(
    _core
    PRIVATE
    pybind11::headers
    "${PROJECT_NAME}_lib"
    )
install(TARGETS _core DESTINATION network_capture)