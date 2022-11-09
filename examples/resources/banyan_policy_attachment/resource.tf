resource "banyan_policy_attachment" "example" {
  policy_id        = banyan_policy_infra.example.id
  attached_to_type = "service"
  attached_to_id   = banyan_service_infra_tcp.example.id
}