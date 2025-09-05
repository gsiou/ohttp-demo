FROM nginx:1.27-alpine
# Optional: show upstream names in error logs
RUN sed -i 's/#error_log.*/error_log \/var\/log\/nginx\/error.log info;/' /etc/nginx/nginx.conf
COPY nginx.conf /etc/nginx/nginx.conf
