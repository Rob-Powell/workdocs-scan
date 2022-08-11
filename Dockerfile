FROM workdocs-scan

ENV PATH="/opt/app:/opt/app/bin:${LAMBDA_TASK_ROOT}:${PATH}"
ENV LD_LIBRARY_PATH="/opt/app/lib:${LD_LIBRARY_PATH}"

COPY lambda_function.py ${LAMBDA_TASK_ROOT}
WORKDIR ${LAMBDA_TASK_ROOT}
CMD [ "lambda_function.lambda_handler" ]