cmake_minimum_required(VERSION 3.12)
project(tiny-aes C)

# Habilitar suporte a OpenMP
find_package(OpenMP REQUIRED)

# Adiciona o tiny-aes como uma biblioteca
add_library(tiny-aes aes.c)

# Inclui diretórios para o tiny-aes
target_include_directories(tiny-aes PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})

# Adiciona o executável para o programa principal
add_executable(main main.c)

# Vincula a biblioteca tiny-aes ao executável principal
target_link_libraries(main PUBLIC tiny-aes)

# Adiciona flags do OpenMP ao executável principal
if(OpenMP_C_FOUND)
    target_link_libraries(main PUBLIC OpenMP::OpenMP_C)
endif()