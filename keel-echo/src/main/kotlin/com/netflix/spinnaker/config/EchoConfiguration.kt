package com.netflix.spinnaker.config

import com.fasterxml.jackson.databind.ObjectMapper
import com.netflix.spinnaker.config.okhttp3.OkHttpClientProvider
import com.netflix.spinnaker.keel.echo.EchoService
import okhttp3.HttpUrl
import okhttp3.HttpUrl.Companion.toHttpUrlOrNull
import org.springframework.beans.factory.BeanCreationException
import org.springframework.beans.factory.annotation.Value
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import retrofit2.Retrofit
import retrofit2.converter.jackson.JacksonConverterFactory

@Configuration
class EchoConfiguration {
  @Bean
  fun echoEndpoint(@Value("\${echo.base-url}") echoBaseUrl: String): HttpUrl =
    echoBaseUrl.toHttpUrlOrNull()
      ?: throw BeanCreationException("Invalid URL: $echoBaseUrl")

  @Bean
  fun echoService(
    echoEndpoint: HttpUrl,
    objectMapper: ObjectMapper,
    clientProvider: OkHttpClientProvider
  ): EchoService =
    Retrofit.Builder()
      .addConverterFactory(JacksonConverterFactory.create(objectMapper))
      .baseUrl(echoEndpoint)
      .client(clientProvider.getClient(DefaultServiceEndpoint("echo", echoEndpoint.toString())))
      .build()
      .create(EchoService::class.java)
}
