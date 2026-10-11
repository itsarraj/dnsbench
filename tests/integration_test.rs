use dnsbench::wire::RecordType;
use dnsbench::{
    audit_propagation, format_benchmark_table, format_propagation_report, query_dns,
    run_benchmark, Resolver,
};
use std::time::Duration;
use tokio::net::UdpSocket;

fn build_mock_dns_response(query_pkt: &[u8], answer_ip: [u8; 4]) -> Vec<u8> {
    let id = [query_pkt[0], query_pkt[1]];
    let mut resp = Vec::new();
    resp.extend_from_slice(&id);
    resp.extend_from_slice(&[0x81, 0x80]); // QR=1, RD=1, RA=1, Rcode=0
    resp.extend_from_slice(&[0x00, 0x01]); // QDCOUNT=1
    resp.extend_from_slice(&[0x00, 0x01]); // ANCOUNT=1
    resp.extend_from_slice(&[0x00, 0x00]); // NSCOUNT=0
    resp.extend_from_slice(&[0x00, 0x00]); // ARCOUNT=0

    // Echo question from query
    let q_slice = &query_pkt[12..];
    resp.extend_from_slice(q_slice);

    // Answer: Pointer to offset 12 (QNAME)
    resp.extend_from_slice(&[0xC0, 0x0C]);
    resp.extend_from_slice(&[0x00, 0x01]); // Type A
    resp.extend_from_slice(&[0x00, 0x01]); // Class IN
    resp.extend_from_slice(&[0x00, 0x00, 0x00, 0x3C]); // TTL = 60s
    resp.extend_from_slice(&[0x00, 0x04]); // RDLength = 4
    resp.extend_from_slice(&answer_ip);

    resp
}

#[tokio::test]
async fn test_live_dns_query_roundtrip() {
    let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let server_addr = server.local_addr().unwrap();

    let server_task = tokio::spawn(async move {
        let mut buf = vec![0u8; 512];
        let (n, from) = server.recv_from(&mut buf).await.unwrap();
        let resp = build_mock_dns_response(&buf[..n], [93, 184, 216, 34]);
        server.send_to(&resp, from).await.unwrap();
    });

    let (response, duration) = query_dns(
        server_addr,
        "example.com",
        RecordType::A,
        false,
        Duration::from_secs(2),
    )
    .await
    .unwrap();

    assert_eq!(response.answers.len(), 1);
    assert_eq!(response.answers[0].data, "93.184.216.34");
    assert_eq!(response.answers[0].record_type, RecordType::A);
    assert!(duration.as_millis() < 500);

    server_task.await.unwrap();
}

#[tokio::test]
async fn test_benchmark_ranking() {
    // Server 1: Fast (0ms delay)
    let s1 = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let s1_addr = s1.local_addr().unwrap();
    let s1_task = tokio::spawn(async move {
        let mut buf = vec![0u8; 512];
        for _ in 0..3 {
            let (n, from) = s1.recv_from(&mut buf).await.unwrap();
            let resp = build_mock_dns_response(&buf[..n], [10, 0, 0, 1]);
            s1.send_to(&resp, from).await.unwrap();
        }
    });

    // Server 2: Delayed (40ms delay)
    let s2 = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let s2_addr = s2.local_addr().unwrap();
    let s2_task = tokio::spawn(async move {
        let mut buf = vec![0u8; 512];
        for _ in 0..3 {
            let (n, from) = s2.recv_from(&mut buf).await.unwrap();
            tokio::time::sleep(Duration::from_millis(40)).await;
            let resp = build_mock_dns_response(&buf[..n], [10, 0, 0, 1]);
            s2.send_to(&resp, from).await.unwrap();
        }
    });

    let resolvers = vec![
        Resolver {
            name: "Mock Delayed".to_string(),
            addr: s2_addr,
            provider: "Test".to_string(),
        },
        Resolver {
            name: "Mock Fast".to_string(),
            addr: s1_addr,
            provider: "Test".to_string(),
        },
    ];

    let results = run_benchmark(
        &resolvers,
        "test.org",
        RecordType::A,
        3,
        4,
        false,
        Duration::from_secs(2),
    )
    .await;

    assert_eq!(results.len(), 2);
    // Fastest resolver should be ranked #1
    assert_eq!(results[0].resolver.name, "Mock Fast");
    assert_eq!(results[1].resolver.name, "Mock Delayed");
    assert!(results[0].stats.p50_ms < results[1].stats.p50_ms);

    let table = format_benchmark_table(&results, "test.org", RecordType::A, false);
    assert!(table.contains("Mock Fast"));
    assert!(table.contains("Mock Delayed"));

    s1_task.await.unwrap();
    s2_task.await.unwrap();
}

#[tokio::test]
async fn test_propagation_drift_audit() {
    // Resolver A returns 1.1.1.1
    let ra = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let ra_addr = ra.local_addr().unwrap();
    let ra_task = tokio::spawn(async move {
        let mut buf = vec![0u8; 512];
        let (n, from) = ra.recv_from(&mut buf).await.unwrap();
        let resp = build_mock_dns_response(&buf[..n], [1, 1, 1, 1]);
        ra.send_to(&resp, from).await.unwrap();
    });

    // Resolver B returns 2.2.2.2 (drift!)
    let rb = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let rb_addr = rb.local_addr().unwrap();
    let rb_task = tokio::spawn(async move {
        let mut buf = vec![0u8; 512];
        let (n, from) = rb.recv_from(&mut buf).await.unwrap();
        let resp = build_mock_dns_response(&buf[..n], [2, 2, 2, 2]);
        rb.send_to(&resp, from).await.unwrap();
    });

    let resolvers = vec![
        Resolver {
            name: "Resolver Alpha".to_string(),
            addr: ra_addr,
            provider: "Alpha".to_string(),
        },
        Resolver {
            name: "Resolver Beta".to_string(),
            addr: rb_addr,
            provider: "Beta".to_string(),
        },
    ];

    let report = audit_propagation(
        &resolvers,
        "app.io",
        RecordType::A,
        false,
        Duration::from_secs(2),
    )
    .await;

    assert!(report.has_drift, "Expected drift detection between Alpha and Beta");
    assert_eq!(report.answer_groups.len(), 2);
    assert_eq!(report.total_queried, 2);
    assert_eq!(report.total_responded, 2);

    let report_str = format_propagation_report(&report, false);
    assert!(report_str.contains("DRIFT DETECTED"));
    assert!(report_str.contains("1.1.1.1"));
    assert!(report_str.contains("2.2.2.2"));

    ra_task.await.unwrap();
    rb_task.await.unwrap();
}
