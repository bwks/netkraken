use futures::StreamExt;

use crate::core::common::HostRecord;
use crate::core::konst::BUFFER_SIZE;

pub async fn resolve_host(hosts: Vec<HostRecord>) -> Vec<HostRecord> {
    let lookup_data: Vec<HostRecord> = futures::stream::iter(hosts)
        .map(|host| {
            async move {
                //
                HostRecord::new(&host.host, host.port).await
            }
        })
        .buffer_unordered(BUFFER_SIZE)
        .collect()
        .await;

    lookup_data
}
