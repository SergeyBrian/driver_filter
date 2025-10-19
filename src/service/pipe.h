#ifndef H_SRC_SERVICE_PIPE_H
#define H_SRC_SERVICE_PIPE_H

using HANDLE = void *;

namespace pipe {
HANDLE StartWorker(HANDLE stop_event);
}

#endif  // H_SRC_SERVICE_PIPE_H
