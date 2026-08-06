# Instructor notes

## Effort-based weekly review

A simple ten-point rubric can remain independent of test success:

| Evidence | Points |
|---|---:|
| Meaningful attempt at the requested modules | 4 |
| Work integrates with the cumulative library | 2 |
| Public tests were run and results recorded | 2 |
| Short reflection on problems and learning | 2 |

A failing public test is useful feedback, not an automatic loss of marks.

## Weekly distribution

Maintain a cumulative template containing all released course/weekXX/
directories. For existing student repositories:

1. add only course/weekNN/ to a new branch;
2. open a PR from that branch to the student's main branch;
3. let the student merge it;
4. run the cumulative public workflow.

Because the PR is additive and instructor-owned paths are separate, source
conflicts should be exceptional.

For Classroom 50 or another GitHub Classroom system, automate the branch and PR
creation with the GitHub CLI if the platform does not provide course-material
sync. Verify current platform behavior before the semester because these tools
can change.

## Challenge policy

Challenges bind only to 127.0.0.1 and request port 0 so the operating system
chooses a free port. Tests use context managers for guaranteed shutdown,
timeouts, fresh secrets, and query limits. Local source inspection is acceptable
because this is an effort-based educational assignment, not a cheat-resistant
competition.

