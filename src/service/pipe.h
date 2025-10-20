#ifndef H_SRC_SERVICE_PIPE_H
#define H_SRC_SERVICE_PIPE_H

#ifndef _WINDEF_
using HANDLE = void *;
#endif

namespace pipe {
HANDLE StartWorker(HANDLE stop_event);
}

#endif  // H_SRC_SERVICE_PIPE_H
