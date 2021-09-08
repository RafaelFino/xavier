#!/bin/bash
# references:
# https://gist.github.com/asukakenji/f15ba7e588ac42795f421b48b8aede63
# https://github.com/golang/go/blob/master/src/go/build/syslist.go

# build code
os_archs=(
    #darwin/amd64
    linux/amd64
    windows/amd64
)

__dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
__proj_dir="$(dirname "$__dir")"

bin_name=${__proj_dir##*/}
build_dir="${__proj_dir}/bin"

built=()
md5sum=""

printf "\e[33m%s\e[39m\tStarting build process: %s" "[EXEC]" 
go version

printf "\e[33m%s\e[39m\tgo mod tidy...\n" "[EXEC]"
go mod tidy

printf "\e[33m%s\e[39m\tgo mod vendor...\n" "[EXEC]"
go mod vendor

printf "\e[33m%s\e[39m\tgo fmt...\n" "[EXEC]"
for target in $(find . -name '*.go' ! -path '*/vendor/*');
do
    if go fmt ${target} ; then
        printf "\e[92m%s\e[39m\tgo fmt -> %s\n" "[DONE]" "${target}"
    else
        printf "\e[1;91m%s\e[0;39m\tgo fmt -> %s\n" "[FAIL]" "${target}"
        exit 1
    fi
done

printf "\e[33m%s\e[39m\tgo test...\n" "[EXEC]"
go test ./...

if [ -d "./cmd" ]; then
    for target in  $(find ./cmd -name '*.go');
    do
        printf "\e[1m\nStating build process to %s -> %s\n\e[0;39m" ${bin_name} ${target}

        for os_arch in "${os_archs[@]}"
        do
            goos=${os_arch%/*}
            goarch=${os_arch#*/}
            arch_path="x86_64"
            bin_name=$(basename $(dirname "${target}"))
            output_bin=${build_dir}/${goos}/${arch_path}/${bin_name}

            printf "\e[33m%s\e[39m\tBuilding %s[%s]...\n" "[BUILD]" "${goos}" "${goarch}"

            if GOOS=${goos} GOARCH=${goarch} go build -mod=vendor -o ${output_bin} -a -ldflags "-s -w" ${target} ; then
                built+=(${output_bin})
                md5sum=$(md5sum $output_bin)
                printf "\e[92m%s\e[39m\t%s.md5\n" "[DONE]" "${md5sum}"
                echo "${md5sum}" > ${output_bin}.md5
            else
                printf "\e[1;91m%s\e[0;39m\t%s\n" "[FAIL]" "${output_bin}"
            fi
        done
    done

    printf "\nOutput:\n"
    for output in "${built[@]}"
    do
        chmod +x ${output}
        printf "\t%s\n" ${output}
    done
fi