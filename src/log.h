#ifndef LOG_H
#define LOG_H

#define log(fmt) do { fprintf(stdout, fmt "\n"); fflush(stdout); } while (0);
#define logf(fmt, ...) do { fprintf(stdout, fmt "\n", __VA_ARGS__); fflush(stdout); } while (0);

#define fatalf(fmt, ...) do { fprintf(stderr, fmt "\n", __VA_ARGS__); exit(1); } while (0);
#define fatal(fmt) do { fprintf(stderr, fmt "\n"); exit(1); } while (0);

#endif
