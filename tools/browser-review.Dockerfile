FROM mcr.microsoft.com/playwright:v1.56.1-noble
RUN npm install --prefix /opt/trace playwright@1.56.1
ENV NODE_PATH=/opt/trace/node_modules
