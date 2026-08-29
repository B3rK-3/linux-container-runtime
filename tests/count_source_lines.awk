# Count runtime source lines the way the 550-line budget defines them: a line
# counts when it holds an actual statement, declaration, or directive. Comments
# (block and line, string literals preserved), blank lines, and lines made up
# only of braces and punctuation are excluded.
BEGIN {
    block_comment = 0
}

{
    in_string = ""
    line_comment = 0
    rendered = ""
    length_of_line = length($0)
    position = 1

    while (position <= length_of_line) {
        character = substr($0, position, 1)
        following = (position < length_of_line) ? substr($0, position + 1, 1) : ""

        if (block_comment) {
            if (character == "*" && following == "/") {
                block_comment = 0
                position += 2
                continue
            }
            position++
            continue
        }

        if (line_comment) {
            break
        }

        if (in_string != "") {
            rendered = rendered character
            if (character == "\\") {
                rendered = rendered following
                position += 2
                continue
            }
            if (character == in_string) {
                in_string = ""
            }
            position++
            continue
        }

        if (character == "/" && following == "*") {
            block_comment = 1
            position += 2
            continue
        }

        if (character == "/" && following == "/") {
            line_comment = 1
            continue
        }

        if (character == "\"" || character == "'") {
            in_string = character
        }

        rendered = rendered character
        position++
    }

    sub(/[[:space:]]+$/, "", rendered)

    if (rendered ~ /^[[:space:]]*$/) next
    if (rendered ~ /^[[:space:]]*[{}\(\)\[\];,]+[[:space:]]*$/) next

    counted++
}

END {
    print counted + 0
}
