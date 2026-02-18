###############################################################################
# SECURITY MODULE — OUTPUTS
###############################################################################

output "guardduty_detector_id" {
  description = "ID of the GuardDuty detector"
  value       = var.enable_guardduty ? aws_guardduty_detector.main[0].id : ""
}

output "config_recorder_id" {
  description = "ID of the AWS Config configuration recorder"
  value       = var.enable_config ? aws_config_configuration_recorder.main[0].id : ""
}
