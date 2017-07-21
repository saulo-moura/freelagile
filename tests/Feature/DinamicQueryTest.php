<?php

namespace Tests\Unit;

use Tests\TestCase;

class DinamicQueryTest extends TestCase
{
    /**
     * Test api search
     */
    public function testApiSearch()
    {
        $header = $this->createAuthHeaderToAdminUser();

        function createCondition($operator, $attribute, $value)
        {
            return [
                'operator' => $operator,
                'attribute' => $attribute,
                'value' => $value
            ];
        }

        $filters = [];
        array_push($filters, createCondition('=', 'email', $this->adminUserData['email']));
        array_push($filters, createCondition('has', 'email', $this->adminUserData['email']));
        array_push($filters, createCondition('startWith', 'email', $this->adminUserData['email']));
        array_push($filters, createCondition('endWith', 'email', $this->adminUserData['email']));

        $query = [
            'model' => 'User',
            'filters' => json_encode($filters)
        ];

        $response = $this->get($this->apiPath . '/dinamicQuery?' . http_build_query($query), $header);
        $response->assertStatus(200);

        $responseData = $response->json();

        $this->assertCount(1, $responseData['items']);
        $this->assertContains($this->adminUserData['email'], collect($responseData['items'])->pluck('email')->all());
    }

    /**
     * Test api load models
     */
    public function testApiLoadModels()
    {
        $response = $this->get($this->apiPath . '/dinamicQuery/models', $this->createAuthHeaderToAdminUser());
        $response->assertStatus(200);

        $responseData = $response->json();

        $response->assertJsonStructure(['*' => [
            'name', 'attributes' => [
                '*' => ['name', 'type']
            ]
        ]]);

        //need to be at least user model
        $this->assertContains('User', collect($responseData)->pluck('name')->all());
    }
}
